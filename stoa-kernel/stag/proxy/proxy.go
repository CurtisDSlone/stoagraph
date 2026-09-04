// Package proxy is the gating-proxy core (Planning/17, Slice 0): the
// transport-agnostic decision at the tool boundary, with NO MCP dependency. An
// external agent proposes a tool call; the Gate routes it to a recipe, runs the
// deterministic kernel, and says whether the call may be FORWARDED to the real
// downstream tool. A call is forwarded IFF it is routed AND the kernel verdict is
// Allow — an unrouted tool or any non-Allow verdict is never forwarded.
package proxy

// file-kw: gating proxy tool boundary route recipe eval forward-iff-cleared fail-closed no-model mcp session-id audit-attribution live-predicate revoked crossing-budget per-binding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/argpath"
)

// MetaApprovalToken is a gate-only argument the ORCHESTRATOR attaches on an approved retry: it
// carries the signed release token. It is bound for gating (a recipe proposes it) but is NEVER
// forwarded downstream — the mcpgate strips it before the real tool call. A tool's real args
// never include it.
const MetaApprovalToken = "approval_token"

// signedPlaceholder is the literal a recipe author writes for a signed_equality rule whose
// expected value is minted per-request by a human approval (Stage 5). The proxy ALWAYS resolves
// it to the looked-up token (or "" when unapproved -> the rule fails closed); the literal never
// reaches the kernel, so it can't be presented to bypass the gate.
const signedPlaceholder = "$approved"

// kw: tool call name args raw from the untrusted agent
type ToolCall struct {
	Tool string
	// Args is every top-level argument, canonically rendered — used for the approval fingerprint and
	// the human-facing audit, NOT for the gate decision.
	Args map[string]string
	// Raw is the arguments exactly as the agent sent them. The gate decides on values pulled OUT of
	// this by path (see stag/proxy/argpath), so what the policy judges is the same JSON that is
	// forwarded downstream — not a stringified impression of it.
	Raw json.RawMessage
}

// kw: route recipe hash gated-arg for a tool
type Route struct {
	Recipe     stag.Recipe
	RecipeHash string
	GateArg    string
	// Sequenced marks a route that exists ONLY so a recipe's `invoke` can authorize calls to it.
	// Such a tool is not advertised to the agent AND is unreachable without a live Grant: an
	// agent that guesses the name is denied, not merely unlisted. Hiding is a convenience; the
	// grant is the enforcement.
	//
	// The zero value is FALSE — an ordinary advertised route — deliberately. Routes are built by
	// struct literal throughout the codebase and by the router package; a flag that had to be set
	// to true for normal behaviour would silently unreach every existing route the moment it was
	// added. The safe, common case must be what you get by writing nothing.
	Sequenced  bool
	RecipeName string // for audit/approval display; not load-bearing
	// Server is the MCP server this tool is dispatched to. It is part of the ROUTE, not something the
	// gate works out from what happens to be connected: a route must mean the same thing tomorrow, when
	// another server that also exposes this tool name has been registered.
	Server string
	// Tool is the tool's name ON THE DOWNSTREAM SERVER — what gets called when a decision clears.
	// It is NOT the Router key: the key is the ADVERTISED name (AdvertisedName(Server, Tool)), which is
	// what the agent calls. Keeping both is what lets two servers expose the same tool name and each be
	// routed to its own recipe.
	Tool string
}

// Approvals is the gate-side store for the human-approval loop (Stage 5). It is OPTIONAL: a nil
// Approvals disables the loop (an escalate stays a dead-end, as before). Primitive signatures so
// *store.Store satisfies it without either package importing the other.
type Approvals interface {
	// LookupApproved returns the signed release token for an action fingerprint iff a row for it
	// is currently `approved`. ok=false (token "") otherwise.
	LookupApproved(ctx context.Context, fingerprint string) (token string, id string, ok bool, err error)
	// RecordPending logs an escalated action awaiting approval (idempotent per id). created=true
	// means a NEW approval needs a human -> the caller fires the webhook.
	RecordPending(ctx context.Context, id, tool, fingerprint, argsJSON, recipe, recipeHash string) (created bool, err error)
	// Consume marks an approved release spent (one-time); a replay then re-escalates.
	Consume(ctx context.Context, id string) error
}

// PendingNotice is what the gate hands OnEscalate when a fresh approval is recorded (the webhook
// payload). It is push-notification only; the store row is the source of truth.
type PendingNotice struct {
	ID          string `json:"id"`
	Tool        string `json:"tool"`
	Fingerprint string `json:"fingerprint"`
	ArgsJSON    string `json:"args"`
	Recipe      string `json:"recipe"`
}

// Router maps an ADVERTISED tool name (<server>__<tool>, see AdvertisedName) to its route.
//
// The key is the advertised name and not the bare tool name, because the bare name is not unique
// across a fleet: GitHub's server and a local one may both expose `search_code`. Keying on the tool
// alone made the two collide — the second route silently repointed the first at a different server —
// which is precisely the "a policy that quietly changes when you add a server" failure the gate is
// supposed to make impossible. The advertised name is unique by construction.
// kw: router advertised name to route unique-per-fleet
type Router map[string]Route

// kw: sink egress record release event (egress.JSONLSink / broker.MemSink satisfy this)
type Sink interface {
	Record(ctx context.Context, d stag.DecisionRecord) error
}

// kw: decision tool verdict forward value events fault approval-id
type Decision struct {
	Tool       string
	Verdict    stag.Verdict
	Forward    bool
	Value      string
	Events     []stag.ReleaseEvent
	Fault      string
	ApprovalID string // set when an escalate is (or awaits) a human approval; "" otherwise
	// Authorized is the sequence of calls this recipe's `invoke` steps cleared, for the
	// executor to carry (stag/dispatch). It is EMPTY unless the decision forwarded: a
	// refused decision authorizes nothing. Authorizing a call is not authority to make
	// it — the executor re-crosses every one of these against that tool's own route.
	Authorized []stag.AuthorizedCall
}

// Grant is a ONE-SHOT authorization for exactly one call: the tool, the arguments, and what
// minted it. It makes an unadvertised tool REACHABLE for a single execution and is spent on use.
//
// It is the same primitive as a human approval — bound to a Fingerprint, consumed on use, replay
// refused — with a deterministic minter instead of a person. Source records WHICH, because a
// machine grant must never be readable as though someone approved it.
//
// A grant says WHEN a call may happen. The tool's own recipe still says WHETHER it may: both are
// required, so a sequence cannot launder an action by authorizing it.
// kw: grant one-shot ephemeral authorization fingerprint minted burned provenance
type Grant struct {
	Fingerprint string // Fingerprint(tool, args): binds the EXACT call
	Tool        string
	Source      string // what minted it, e.g. "policy:lab_repair_badport" — never "human"
}

// Authorizations is the ephemeral-grant store. It is deliberately the same shape as Approvals:
// mint, look up, burn.
// kw: authorizations store mint lookup burn ephemeral one-shot
type Authorizations interface {
	// Mint records a grant for exactly one call.
	Mint(ctx context.Context, g Grant) error
	// Lookup returns the live grant for a fingerprint, if one is outstanding.
	Lookup(ctx context.Context, fingerprint string) (Grant, bool, error)
	// Burn spends a grant. A replay then finds nothing and is denied.
	Burn(ctx context.Context, fingerprint string) error
}

// kw: gate routes sink deterministic tool-boundary approvals notify crossing-budget
type Gate struct {
	Routes    Router
	Sink      Sink
	Approvals Approvals // optional: enables the escalate->approval loop (Stage 5)
	// Authorizations backs the one-shot grants that make an unadvertised route reachable. A nil
	// store means unadvertised routes are UNREACHABLE — absent machinery fails closed.
	Authorizations Authorizations
	OnEscalate     func(ctx context.Context, n PendingNotice) // optional: push notify (webhook) on a fresh escalation
	// Budget is the per-DISPATCHED-SESSION forwarded-crossing cap N (Planning/34 §6.2). The leakage bound
	// is a per-session ceiling (N crossings), so it is only a guarantee if N is enforced at the gate — the
	// reference harness's maxTurns is client-side and an injected agent need not honour it. nil means
	// unlimited (the budget is off).
	//
	// It is a POINTER, and its lifetime is the dispatcher's session binding — NOT the MCP transport
	// session. The untrusted agent can re-initialize the MCP transport at will (drop the Mcp-Session-Id,
	// POST initialize again), which mints a fresh gating server; if the counter lived in the gating server
	// the agent would reset N to zero every reconnect. So the same *CrossingBudget is created once per
	// bound token (sessiond.Registry) and shared across every gating server built for that token. Decide
	// itself stays stateless; the budget is consulted in the transport layer (mcpgate.gatingHandler).
	Budget *CrossingBudget
	// Session is the non-reversible id of the bound session this gate serves, stamped onto every
	// decision it records so the audit can group runs by agent. Empty for a gate that is not serving a
	// bound session (the control plane's preview gate).
	Session string
	// Live reports whether this gate's session binding still exists. It is consulted on EVERY request,
	// because the transport resolves a session ONCE at connect: the MCP SDK builds the server for a new
	// transport session and then reuses it, so a check that lives only at connect never runs again and
	// an already-connected agent outlives its own revocation. Revoking has to reach the agent already
	// inside, not just lock the door behind it.
	//
	// nil means "always live" — a gate with no session to revoke (the control plane's preview gate).
	Live func() bool
}

// kw: revoked session withdrawn per-request live evict already-connected
// Revoked reports whether this gate's binding has been withdrawn. A gate with no Live predicate is
// never revoked (fail-safe for gates that have no session).
func (g Gate) Revoked() bool { return g.Live != nil && !g.Live() }

// kw: session id audit digest never-the-token bearer-credential attribution
// SessionID derives the audit-visible id of a session token. It is a truncated SHA-256 of the token,
// NOT the token: the token is the agent's bearer credential and must never be written to a log that
// is read by more parties than may hold it. Truncation to 128 bits keeps the log readable while
// leaving the id collision-resistant for this purpose.
func SessionID(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

// CrossingBudget is a session's forwarded-crossing counter. Reserve() is taken before a decision and
// Release()d if the call does not forward, so the count tracks ACTUAL crossings. A nil *CrossingBudget,
// or one with limit <= 0, is unlimited (the budget is off). It is safe for concurrent use and for a nil
// receiver, so the transport layer can call it unconditionally.
type CrossingBudget struct {
	mu    sync.Mutex
	count int
	limit int
}

// NewCrossingBudget returns a budget of at most limit forwarded crossings (limit <= 0 = unlimited).
func NewCrossingBudget(limit int) *CrossingBudget { return &CrossingBudget{limit: limit} }

// Reserve claims one crossing if the budget allows, atomically. Returns false when the session has
// already used its limit — the caller then denies fail-closed without deciding. nil/unlimited => true.
func (c *CrossingBudget) Reserve() bool {
	if c == nil || c.limit <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count >= c.limit {
		return false
	}
	c.count++
	return true
}

// Release returns a reservation taken by Reserve() when the call turned out not to cross (deny/escalate).
func (c *CrossingBudget) Release() {
	if c == nil || c.limit <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count > 0 {
		c.count--
	}
}

// kw: decide route eval forward-iff-cleared record fail-closed approval-loop
func (g Gate) Decide(ctx context.Context, call ToolCall) Decision {
	route, ok := g.Routes[call.Tool]
	if !ok {
		// fail closed (inv 8/10): a tool with no policy is denied, never forwarded. It is still RECORDED
		// — "the agent reached for a tool it was never granted" is exactly the evidence an auditor wants,
		// and dropping it would leave the most suspicious call of all invisible.
		d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false, Fault: "no recipe for tool " + call.Tool}
		g.record(ctx, d, "", "")
		return d
	}

	// REACHABILITY, before anything else about this call is judged.
	//
	// An unadvertised route is not offered to the agent, but hiding is only a convenience: the
	// tool must also be UNREACHABLE. It becomes reachable for exactly one call when a recipe's
	// `invoke` mints a Grant for that call's fingerprint, and is spent on use. So an agent that
	// guesses the name is denied, a call outside its sequence is denied, and a replay is denied.
	//
	// A nil store means no grant can exist, so every unadvertised route is unreachable — absent
	// machinery fails closed (inv 8).
	grantFP := ""
	if route.Sequenced {
		fp := Fingerprint(call.Tool, call.Args)
		ok := false
		if g.Authorizations != nil {
			if _, live, err := g.Authorizations.Lookup(ctx, fp); err == nil && live {
				ok, grantFP = true, fp
			}
		}
		if !ok {
			d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false,
				Fault: "no live authorization for " + call.Tool + " (unadvertised: reachable only from the sequence that authorizes it)"}
			g.record(ctx, d, route.RecipeName, route.RecipeHash)
			return d
		}
	}

	// GateArg is one PATH (single-arg), or a comma-separated list of them (multi-arg): each listed path
	// binds a `propose out: <slot>` slot, so one recipe can decide from several arguments
	// (e.g. "namespace,replicas"). A path may reach INTO the payload — `files[].path` — and may select
	// several values, in which case every one of them must clear. See stag/proxy/argpath.
	//
	// An EMPTY GateArg means the tool takes no arguments to judge: the route is the authorization. One
	// empty proposal is bound so the recipe still runs and can still deny or escalate.
	// COVERAGE (the argument-level half of complete mediation). Gating the paths an author listed
	// says nothing about the arguments they did NOT list — and an unlisted argument is forwarded
	// verbatim. So every argument the agent actually sends must be ACCOUNTED for: gated (covered by
	// a GateArg path) or declared passthrough in the recipe. An unaccounted argument denies the call.
	//
	// Without this, a policy that gates `to` on wire_transfer(to, amount) looks complete and lets any
	// `amount` through. The tool is routed, the listed path clears, and the effect is unbounded.
	if cerr := coverage(route, call); cerr != nil {
		d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false, Fault: cerr.Error()}
		g.record(ctx, d, route.RecipeName, route.RecipeHash)
		return d
	}

	slots, perr := g.gatedValues(route, call)
	if perr != nil {
		// A path that lands on an object, or on an array without [], cannot be judged. Denying is the
		// only honest answer — the alternative is to stringify the composite and pretend a rule looked
		// at it, which is the bug this replaced.
		d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false, Fault: perr.Error()}
		g.record(ctx, d, route.RecipeName, route.RecipeHash)
		return d
	}
	value := auditValue(slots)

	// STAGE 5: if the recipe has a signed_equality "$approved" gate, resolve it against the
	// approval store. LookupApproved returns the human-minted token for this exact action iff it
	// is currently approved; we ALWAYS substitute (token or "") so the placeholder never evals.
	recipe := route.Recipe
	fingerprint, approvedID := "", ""
	needsApproval := g.Approvals != nil && recipeHasApprovalGate(route.Recipe)
	if needsApproval {
		// fingerprint binds the WHOLE action (all call args, minus the token), not just the gated
		// subset — so an approval authorizes exactly this call, not every call sharing a gated value.
		fingerprint = Fingerprint(call.Tool, call.Args)
		token := ""
		if tok, id, okA, err := g.Approvals.LookupApproved(ctx, fingerprint); err == nil && okA {
			token, approvedID = tok, id
		}
		recipe = resolveApproved(route.Recipe, token)
	}

	res, everr := evalSlots(recipe, slots, route.RecipeHash, strings.Contains(route.GateArg, ","))
	if everr != nil {
		// a deny: withhold the raw proposed value from the signed log (see redactedValue).
		d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false, Value: redactedValue(slots), Fault: everr.Error()}
		g.record(ctx, d, route.RecipeName, route.RecipeHash)
		return d
	}

	// forward IFF the whole-recipe verdict is Allow. A Deny, an Escalate, or a Fault never
	// reaches the downstream tool (complete mediation at the boundary).
	forward := res.Verdict == stag.Allow

	if needsApproval {
		switch {
		case res.Verdict == stag.Allow && approvedID != "":
			_ = g.Approvals.Consume(ctx, approvedID) // one-time: burn the release on use
		case res.Verdict == stag.Escalate && approvedID == "":
			id := idFor(fingerprint)
			argsJSON := marshalArgs(call.Args) // the full action, for the dashboard
			if created, _ := g.Approvals.RecordPending(ctx, id, call.Tool, fingerprint, argsJSON, route.RecipeName, route.RecipeHash); created && g.OnEscalate != nil {
				g.OnEscalate(ctx, PendingNotice{ID: id, Tool: call.Tool, Fingerprint: fingerprint, ArgsJSON: argsJSON, Recipe: route.RecipeName})
			}
		}
	}

	// A DENY or ESCALATE withholds the raw proposed value from the signed log (redactedValue): the model
	// can propose arbitrary free-text and force EITHER verdict at will (any value fails a closed set;
	// any value hits an on_fail:escalate gate), so recording it verbatim is a covert channel through the
	// audit log — and an escalate does not even consume the crossing budget, so the channel would be
	// unbounded. Only ALLOW keeps its value: it is a released closed-set member, hence bounded. The human
	// approver still sees the exact escalated action via the approval store's argsJSON (RecordPending),
	// not this field, so redacting it here loses nothing for review.
	auditVal := value
	if res.Verdict == stag.Deny || res.Verdict == stag.Escalate {
		auditVal = redactedValue(slots)
	}
	d := Decision{Tool: call.Tool, Verdict: res.Verdict, Forward: forward, Value: auditVal, Events: res.Events, Fault: res.Fault, ApprovalID: approvalIDForView(res.Verdict, approvedID, fingerprint, needsApproval)}
	// a refused decision hands out no plan: the kernel already retracted them, and the
	// boundary states it again so no caller can read a sequence off a call that was denied.
	if forward {
		d.Authorized = res.Authorized
		// Spend the grant: it authorized ONE call and that call is now happening. A refused call
		// does NOT burn — it never happened, so the authorization is still owed and expires with
		// its sequence rather than with a refusal.
		if grantFP != "" && g.Authorizations != nil {
			_ = g.Authorizations.Burn(ctx, grantFP)
		}
	}
	g.record(ctx, d, route.RecipeName, route.RecipeHash)
	return d
}

// record writes exactly ONE leaf per decision — allow, deny, or escalate alike.
//
// Releases ride along ONLY when the call was forwarded. A multi-arg recipe evaluates every sink, so a
// DENIED call can still have individually-cleared sinks (owner=mallory fails while repo=stoagraph
// passes). Recording those as releases would put a crossing in the tamper-evident log that never
// happened — the audit would claim the agent read a repo the gate actually blocked. The record states
// what HAPPENED, not what merely evaluated.
//
// Egress stays best-effort and off the enforcement path (inv 9): a sink error never changes the verdict.
func (g Gate) record(ctx context.Context, d Decision, recipeName, recipeHash string) {
	if g.Sink == nil {
		return
	}
	rec := stag.DecisionRecord{
		Session:    g.Session,
		Tool:       d.Tool,
		Verdict:    d.Verdict.String(),
		Forwarded:  d.Forward,
		Value:      d.Value,
		Recipe:     recipeName,
		RecipeHash: recipeHash,
		Fault:      d.Fault,
	}
	if d.Forward { // released iff forwarded
		rec.Events = d.Events
	}
	_ = g.Sink.Record(ctx, rec)
}

// RecordDenied records a fail-closed DENY for a call refused BEFORE evaluation — e.g. a session
// crossing-budget overflow, where the transport layer must deny without letting Decide forward-and-record
// a crossing it is about to block. It reuses the one record path so the signed log stays uniform: a
// single leaf, no release (nothing crossed), the reason in Fault. The value is withheld (a refused call
// records no proposed bytes; see redactedValue). Returns the Decision so the caller can shape the refusal.
func (g Gate) RecordDenied(ctx context.Context, call ToolCall, fault string) Decision {
	route := g.Routes[call.Tool] // zero Route if unrouted — empty name/hash is correct then
	d := Decision{Tool: call.Tool, Verdict: stag.Deny, Forward: false, Fault: fault}
	g.record(ctx, d, route.RecipeName, route.RecipeHash)
	return d
}

// Covered reports the set of TOP-LEVEL argument names a route accounts for: the head segment of
// every gated path, plus the recipe's declared passthrough list, plus the gate-only approval token
// (which is never forwarded downstream).
//
// A path may reach into the payload — `files[].path` gates the *contents* of `files`, and the
// top-level argument it accounts for is `files`. That is the right granularity for coverage: the
// question is whether the argument was JUDGED at all, and a path into it means it was.
// kw: coverage accounted gated passthrough top-level heads
func Covered(route Route) map[string]bool {
	acc := map[string]bool{MetaApprovalToken: true}
	for _, p := range splitGateArg(route.GateArg) {
		if h := headSegment(p); h != "" {
			acc[h] = true
		}
	}
	for _, a := range route.Recipe.PassThrough {
		acc[a] = true
	}
	return acc
}

// headSegment is the top-level argument a gate path descends from: `files[].path` -> `files`.
func headSegment(path string) string {
	if path == "" {
		return ""
	}
	seg := path
	if i := strings.Index(path, "."); i >= 0 {
		seg = path[:i]
	}
	return strings.TrimSuffix(seg, "[]")
}

// coverage denies a call carrying any argument the policy does not account for.
//
// This is decide-time enforcement, over the keys the agent ACTUALLY SENT — so it holds even when a
// downstream's declared schema is permissive, lies, or allows additional properties. Bind-time
// checks the schema (see CoverageGaps); this checks reality.
func coverage(route Route, call ToolCall) error {
	acc := Covered(route)
	for _, k := range topLevelKeys(call) {
		if !acc[k] {
			return fmt.Errorf("argument %q is neither gated nor declared passthrough — the policy does not account for it", k)
		}
	}
	return nil
}

// CoverageGaps reports the tool-schema arguments a route accounts for NEITHER by gating NOR by an
// explicit passthrough declaration. Bind-time uses it to refuse a route whose policy has holes,
// before any agent ever calls the tool. An empty result means the policy covers the whole schema.
// kw: coverage bind-time schema properties unaccounted
func CoverageGaps(route Route, schemaArgs []string) []string {
	acc := Covered(route)
	var gaps []string
	for _, a := range schemaArgs {
		if !acc[a] {
			gaps = append(gaps, a)
		}
	}
	sort.Strings(gaps)
	return gaps
}

// topLevelKeys lists the argument names the agent sent, from the RAW JSON when present (the exact
// bytes that would be forwarded) and from Args otherwise (a transport-agnostic embedder).
func topLevelKeys(call ToolCall) []string {
	if len(call.Raw) > 0 {
		var m map[string]json.RawMessage
		if json.Unmarshal(call.Raw, &m) == nil {
			out := make([]string, 0, len(m))
			for k := range m {
				out = append(out, k)
			}
			sort.Strings(out) // deterministic: the FIRST unaccounted arg named is stable
			return out
		}
		// Unparseable arguments are not a coverage question; gatedValues/argpath will fail closed.
		return nil
	}
	out := make([]string, 0, len(call.Args))
	for k := range call.Args {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// maxEvals bounds how many times one call may be evaluated. A gated path over an array is judged per
// element, and two such paths multiply, so a hostile payload with a huge array is otherwise a way to
// burn the gate's CPU. Past the bound we DENY: refusing to decide is the fail-closed answer, and no
// legitimate policy needs to judge hundreds of values in one call.
const maxEvals = 256

// slot is one gated path, its recipe slot name, and every value the path selected.
type slot struct {
	name string   // the recipe's `propose out:` name (the path's last segment)
	vals []string // one entry for a scalar path; N for a path crossing []
}

// gatedValues resolves each gated path against the call's RAW arguments.
//
// The values come out of the JSON the agent actually sent, so the gate judges the same bytes that get
// forwarded. The old code read fmt.Sprint of a decoded map, which rendered a payload as Go memory
// syntax and made it unjudgeable.
func (g Gate) gatedValues(route Route, call ToolCall) ([]slot, error) {
	// The package is transport-agnostic: an embedder that only has flat arguments may pass Args alone.
	// Synthesize the document from them so a flat path still resolves. When Raw IS present (every MCP
	// caller) it wins, because it is the exact JSON that will be forwarded.
	raw := call.Raw
	if len(raw) == 0 && len(call.Args) > 0 {
		if b, err := json.Marshal(call.Args); err == nil {
			raw = b
		}
	}

	paths := splitGateArg(route.GateArg)
	out := make([]slot, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			// no argument to judge — the route itself is the authorization
			out = append(out, slot{name: "", vals: []string{""}})
			continue
		}
		if p == MetaApprovalToken {
			// the gate-only approval token is not in the tool's arguments schema; it rides alongside
			out = append(out, slot{name: p, vals: []string{call.Args[MetaApprovalToken]}})
			continue
		}
		vals, err := argpath.Extract(raw, p)
		if err != nil {
			return nil, fmt.Errorf("gate path: %w", err)
		}
		out = append(out, slot{name: slotName(p), vals: vals})
	}
	return out, nil
}

// slotName is the recipe slot a path binds: its last segment. `files[].path` proposes `path`, so a
// recipe reads the way an author thinks ("the path of each file"), not the way the JSON is nested.
func slotName(path string) string {
	seg := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		seg = path[i+1:]
	}
	return strings.TrimSuffix(seg, "[]")
}

// evalSlots runs the recipe over every combination of the selected values and ANDs the verdicts.
//
// A path over an array selects many values, and EVERY one must clear: an array is not a way to slip one
// bad element past a rule the other elements satisfy. The rollup is conjunctive and fail-closed — any
// Deny denies, any Escalate escalates, and only an all-Allow allows.
func evalSlots(recipe stag.Recipe, slots []slot, hash string, multi bool) (stag.EvalResult, error) {
	total := 1
	for _, s := range slots {
		total *= max(len(s.vals), 1)
		if total > maxEvals {
			return stag.EvalResult{}, fmt.Errorf("gate: %d value combinations exceeds the %d-evaluation bound — refusing to decide", total, maxEvals)
		}
	}

	combos := cartesian(slots)
	out := stag.EvalResult{Verdict: stag.Allow}
	for i, c := range combos {
		var r stag.EvalResult
		if multi {
			r = stag.EvalArgs(recipe, c, hash)
		} else {
			// single path: the one proposal binds everywhere in the recipe
			r = stag.Eval(recipe, c[slots[0].name], hash)
		}
		if i == 0 {
			out = r
			continue
		}
		out.Verdict = andVerdict(out.Verdict, r.Verdict)
		out.Events = append(out.Events, r.Events...)
		if out.Fault == "" {
			out.Fault = r.Fault
		}
		// Authorizations are NOT accumulated across combinations. A fan-out evaluates the
		// same recipe once per value combination, so appending would let one proposal
		// multiply the actions a policy authorizes (N elements -> N copies of the
		// sequence). The authorized sequence is the RECIPE's; the fold keeps the first
		// and lets the verdict decide whether any of it survives.
		if len(r.Authorized) != len(out.Authorized) {
			// combinations disagree on what cleared: refuse the whole decision (inv 8)
			out.Verdict = stag.Deny
			if out.Fault == "" {
				out.Fault = "gate: value combinations authorized different sequences"
			}
		}
	}
	return out, nil
}

// cartesian expands the slots into every combination of their values, in a deterministic order.
func cartesian(slots []slot) []map[string]string {
	combos := []map[string]string{{}}
	for _, s := range slots {
		next := make([]map[string]string, 0, len(combos)*len(s.vals))
		for _, base := range combos {
			for _, v := range s.vals {
				m := make(map[string]string, len(base)+1)
				for k, bv := range base {
					m[k] = bv
				}
				m[s.name] = v
				next = append(next, m)
			}
		}
		combos = next
	}
	return combos
}

// andVerdict is the fail-closed rollup: Deny beats Escalate beats Allow.
func andVerdict(a, b stag.Verdict) stag.Verdict {
	if a == stag.Deny || b == stag.Deny {
		return stag.Deny
	}
	if a == stag.Escalate || b == stag.Escalate {
		return stag.Escalate
	}
	if a == stag.Allow && b == stag.Allow {
		return stag.Allow
	}
	return stag.Deny // any verdict we do not recognise is a deny
}

// auditValue renders what the gate judged, for the human record: the bare value for a single scalar,
// "k=v k=v" across several, and a bracketed list when a path selected many.
func auditValue(slots []slot) string {
	if len(slots) == 1 && slots[0].name == "" {
		return "" // no gated argument
	}
	if len(slots) == 1 {
		return joinVals(slots[0].vals)
	}
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		if s.name == MetaApprovalToken {
			continue // the gate-only token is never shown in the audit value
		}
		parts = append(parts, s.name+"="+joinVals(s.vals))
	}
	return strings.Join(parts, " ")
}

func joinVals(vs []string) string {
	if len(vs) == 1 {
		return vs[0]
	}
	return "[" + strings.Join(vs, " ") + "]"
}

// withheld is the bounded placeholder a DENY records in place of the model's raw proposed value.
const withheld = "<withheld>"

// redactedValue renders a non-forwarded verdict's audit value with every gated value WITHHELD. On a deny
// or escalate nothing crosses, so the proposed bytes have no release to attest — and recording them
// verbatim would turn the signed, hash-chained log into a covert channel: an observer of the log would
// read attacker-chosen free-text on every such call (the leakage bound assumes a semantic-value observer;
// this closes the Value channel for the verdicts that redact, Planning/34 §6.3). The descriptor keeps the
// gated argument NAMES — which are recipe-structural, so bounded and carrying no per-call choice — and
// withholds only the values. The raw proposed action, when needed for forensics, belongs in a separate
// operator-private capture (the READ log already attests the untrusted source), never the release log.
//
// This closes the VALUE channel only. A denied leaf's Fault may still carry an attacker-chosen substring
// (an unrouted tool name; an unaccounted argument key) — a smaller, separate residual noted in
// Planning/34 §6.3; bounding it trades away the "the agent reached for tool X" evidence, so it is left
// visible by default. ALLOW keeps its canonical value (a released closed-set member — already bounded).
func redactedValue(slots []slot) string {
	if len(slots) == 1 && slots[0].name == "" {
		return "" // no gated argument to speak of
	}
	if len(slots) == 1 {
		return withheld
	}
	parts := make([]string, 0, len(slots))
	for _, s := range slots {
		if s.name == MetaApprovalToken {
			continue
		}
		parts = append(parts, s.name+"="+withheld)
	}
	return strings.Join(parts, " ")
}

// splitGateArg parses a GateArg into its paths: one path (single-arg) or a comma-separated
// list (multi-arg). Empty entries are dropped; a single non-comma arg returns one path.
func splitGateArg(gateArg string) []string {
	out := make([]string, 0, 2)
	for _, a := range strings.Split(gateArg, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		out = append(out, "") // preserves the "missing arg binds \"\"" fail-closed behavior
	}
	return out
}

// Fingerprint canonicalizes an action (tool + its args, EXCLUDING the approval-token meta arg)
// into a stable string. A human approves this exact tuple; the signed release binds to it, and a
// retry with the same args reproduces it. Sorted keys => order-independent.
func Fingerprint(tool string, args map[string]string) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		if k == MetaApprovalToken || k == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(tool)
	for _, k := range keys {
		b.WriteByte('\x1f')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(args[k])
	}
	return b.String()
}

// idFor is the approval id: a short, stable digest of the fingerprint, so re-escalating the same
// action maps to one approval row (idempotent).
func idFor(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:8])
}

// recipeHasApprovalGate reports whether any rule in the recipe is a signed_equality "$approved"
// placeholder — i.e. this recipe participates in the human-approval loop. Cheap; walks steps once.
func recipeHasApprovalGate(r stag.Recipe) bool {
	for i := range r.Steps {
		if isApprovedRule(r.Steps[i].Rule) {
			return true
		}
		for j := range r.Steps[i].Cases {
			if isApprovedRule(r.Steps[i].Cases[j].Rule) {
				return true
			}
		}
	}
	return false
}

func isApprovedRule(rule *stag.ReleaseRule) bool {
	return rule != nil && rule.Kind == stag.RuleSignedEquality && rule.Signed == signedPlaceholder
}

// resolveApproved returns a shallow clone of the recipe with every signed_equality "$approved"
// rule's expected value set to token (which is "" when the action is not currently approved, so
// the rule fails closed). Only rules that need substituting get fresh pointers — the shared
// parsed recipe (held by the router across calls) is never mutated.
func resolveApproved(r stag.Recipe, token string) stag.Recipe {
	steps := make([]stag.Step, len(r.Steps))
	copy(steps, r.Steps) // Step is a value; its *Rule pointers are shared until we replace them
	for i := range steps {
		if isApprovedRule(steps[i].Rule) {
			nr := *steps[i].Rule
			nr.Signed = token
			steps[i].Rule = &nr
		}
		if len(steps[i].Cases) > 0 {
			cs := make([]stag.Case, len(steps[i].Cases))
			copy(cs, steps[i].Cases)
			for j := range cs {
				if isApprovedRule(cs[j].Rule) {
					nr := *cs[j].Rule
					nr.Signed = token
					cs[j].Rule = &nr
				}
			}
			steps[i].Cases = cs
		}
	}
	return stag.Recipe{Ingredients: r.Ingredients, Steps: steps}
}

// marshalArgs renders the gated args as compact JSON for the approval row (dashboard display);
// the approval-token meta arg is omitted (it's not part of the action being approved).
func marshalArgs(args map[string]string) string {
	m := make(map[string]string, len(args))
	for k, v := range args {
		if k != MetaApprovalToken && k != "" {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// approvalIDForView surfaces the approval id on the Decision so the caller/audit can point a human
// at the pending item. Only meaningful for approval-gated escalations.
func approvalIDForView(v stag.Verdict, approvedID, fingerprint string, needsApproval bool) string {
	if !needsApproval {
		return ""
	}
	if v == stag.Escalate {
		return idFor(fingerprint) // the pending id a human must act on
	}
	return approvedID // the id we released (and consumed), if any
}
