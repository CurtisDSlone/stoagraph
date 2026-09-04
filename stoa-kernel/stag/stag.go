// Package stag is the public entry point to the StAG kernel: Eval, the recipe
// evaluator that composes the internal trust/gate/release/record primitives into
// the product's load-bearing guarantee (no non-authoritative value reaches an
// authoritative sink at Allow without both a gate verdict and a recorded
// ReleaseEvent), plus re-exports of the primitive types and constants a caller
// needs to build a Recipe. The primitives themselves are internal and fixed.
package stag

// file-kw: stag public api recipe eval compose kernel invariant facade re-export graph walk branch gate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/record"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/release"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

// Re-exported primitive types (the internal packages stay private).
type (
	TrustClass      = trust.TrustClass
	Verdict         = gate.Verdict
	SinkSensitivity = gate.SinkSensitivity
	RuleKind        = release.RuleKind
	ReleaseRule     = release.ReleaseRule
	ReleaseEvent    = record.ReleaseEvent
	// DecisionRecord is the audit chain's unit: one leaf per DECISION (allow, deny or escalate),
	// carrying its releases only when the call was actually forwarded.
	DecisionRecord = record.DecisionRecord
)

// Re-exported constants, so a caller can build recipes without the internals.
const (
	Untrusted     = trust.Untrusted
	Caller        = trust.Caller
	Authoritative = trust.Authoritative

	Allow    = gate.Allow
	Escalate = gate.Escalate
	Deny     = gate.Deny

	SinkBenign        = gate.SinkBenign
	SinkAuthoritative = gate.SinkAuthoritative

	RuleSetMembership  = release.RuleSetMembership
	RuleSignedEquality = release.RuleSignedEquality
	RuleNumericRange   = release.RuleNumericRange
)

// kw: facade re-exports one hashing discipline one enum register
func CanonicalHash(v any) (string, error) { return record.CanonicalHash(v) }

// kw: parse inverses re-export fail-closed
func ParseTrustClass(s string) (TrustClass, error)           { return trust.ParseTrustClass(s) }
func ParseSinkSensitivity(s string) (SinkSensitivity, error) { return gate.ParseSinkSensitivity(s) }
func ParseRuleKind(s string) (RuleKind, error)               { return release.ParseRuleKind(s) }

// kw: bind graph slot value class origin
type Slot struct {
	Value  string
	Class  TrustClass
	Origin string
}

// kw: recipe node kind propose sink branch gate
type NodeKind int

// kw: node kind constants propose sink branch gate
const (
	NodePropose NodeKind = iota
	NodeSink
	NodeBranch
	NodeGate
	NodeForeach
	NodeInvoke
	NodeAwait
	NodeExit
)

// foreachCap is the fixed max number of elements a foreach may iterate — an
// author-unraisable kernel bound (inv 13); a longer list fails closed.
const foreachCap = 64

// The await bounds are author-unraisable (inv 13), like foreachCap. attempts x delay is
// wall-clock an agent can spend by triggering a sequence, so both ends and their product are
// capped by the kernel — a step that can wait indefinitely is a step that never fails closed.
//
// A recipe that asks for more is a FAULT, not a clamped value: an author who writes 1000
// attempts believes they will get 1000, and silently substituting 32 is a policy that does not
// do what it says.
const (
	awaitAttemptCap = 32            // at most this many polls per await step
	awaitDelayCapMS = 30000         // at most 30s between polls
	awaitTotalCapMS = 5 * 60 * 1000 // and at most 5 minutes of waiting in one step
)

// kw: node kind string canonical register
func (k NodeKind) String() string {
	switch k {
	case NodePropose:
		return "propose"
	case NodeSink:
		return "sink"
	case NodeBranch:
		return "branch"
	case NodeGate:
		return "gate"
	case NodeForeach:
		return "foreach"
	case NodeInvoke:
		return "invoke"
	case NodeAwait:
		return "await"
	case NodeExit:
		return "exit"
	default:
		return "unknown"
	}
}

// kw: parse node kind fail-closed inverse of string
func ParseNodeKind(s string) (NodeKind, error) {
	switch s {
	case "propose":
		return NodePropose, nil
	case "sink":
		return NodeSink, nil
	case "branch":
		return NodeBranch, nil
	case "gate":
		return NodeGate, nil
	case "foreach":
		return NodeForeach, nil
	case "invoke":
		return NodeInvoke, nil
	case "await":
		return NodeAwait, nil
	case "exit":
		return NodeExit, nil
	default:
		return NodeKind(-1), fmt.Errorf("invalid node kind: %q", s) // fail closed (inv 8)
	}
}

// kw: branch case closed predicate forward edge
type Case struct {
	Rule *ReleaseRule
	Goto string
}

// kw: recipe step propose sink branch gate forward-only edges
type Step struct {
	Id          string
	Kind        NodeKind
	Out         string
	In          string
	As          string // foreach: the per-element out-slot bound each iteration
	Sensitivity SinkSensitivity
	Rule        *ReleaseRule
	RuleID      string
	Field       string
	Actor       string
	Goto        string // optional forward edge; "" = fall-through
	Escalate    bool   // gate on-fail: false=Deny (default), true=Escalate
	Cases       []Case // branch
	Default     string // branch
	// invoke: the tool this step AUTHORIZES, and its arguments — each bound to a slot
	// and cleared by ITS OWN rule.
	Tool     string
	ArgRules map[string]ArgRule
	// await: the condition the polled tool's OUTPUT must satisfy, and the bounds on polling.
	// Until is nil on an invoke — one call, no condition.
	Until    *ReleaseRule
	UntilID  string
	Attempts int // number of polls permitted; 1..awaitAttemptCap
	DelayMS  int // milliseconds between polls; 0..awaitDelayCapMS
}

// ArgRule binds one argument of an invoke: which slot supplies it, and which rule must
// clear it.
//
// Each argument carries its own rule because an invoke's arguments are usually different
// KINDS of value — a target name, an operation, a payload. A single rule shared across them
// cannot say which argument may be what: it degenerates into a flat set of permitted strings
// that would clear a payload sitting in the target's slot. Per-argument rules make the policy
// state what it means, and the audit record then names which rule cleared which argument.
// kw: arg rule per-argument slot binding invoke precise
type ArgRule struct {
	Slot   string       // the slot supplying this argument
	Rule   *ReleaseRule // the rule that must clear it; nil never clears (fail closed)
	RuleID string       // the rule's label, recorded on the crossing
}

// kw: recipe ingredients steps
type Recipe struct {
	Ingredients map[string]Slot
	Steps       []Step
	// PassThrough names the tool arguments this policy KNOWINGLY forwards ungated. It is the
	// coverage contract: an argument is either gated (a propose slot fed by a GateArg path) or
	// listed here. An argument that is neither is unaccounted for, and the gate denies the call.
	//
	// It lives in the recipe (not the route) because it is a security decision and must ride in
	// the SemanticHash: widening coverage has to change the policy identity the audit records.
	// A route-side declaration would leave the signed record unable to tell a gated argument from
	// one silently waved through.
	PassThrough []string
}

// AuthorizedCall is one tool call a recipe has AUTHORIZED. The kernel performs no I/O:
// it resolves the call's arguments from slots, clears each against the step's rule, and
// emits this. The executor is transport — and it re-crosses every call through the gate
// against that tool's OWN route and recipe, so authorizing a call is never authority to
// make it. A recipe cannot launder an action by naming it.
// kw: authorized call invoke tool args ordinal executor re-cross
type AuthorizedCall struct {
	StepID  string            `json:"step_id"`
	Tool    string            `json:"tool"`
	Args    map[string]string `json:"args"`
	Ordinal int64             `json:"ordinal"`
	// An AWAIT authorizes a bounded POLL rather than one call: the executor repeats it until the
	// tool's output satisfies Until, or until Attempts is exhausted. The kernel does not poll —
	// that would be I/O — it authorizes the polling and states its limits.
	//
	// Until is nil for an ordinary invoke, which is one call and no condition.
	Until    *ReleaseRule `json:"-"`
	UntilID  string       `json:"until,omitempty"`
	Attempts int          `json:"attempts,omitempty"`
	DelayMS  int          `json:"delay_ms,omitempty"`
}

// kw: sink outcome verdict per sink
type SinkOutcome struct {
	Field    string
	Subject  TrustClass
	Sink     SinkSensitivity
	Released bool
	Verdict  Verdict
}

// kw: gate outcome checkpoint pass fail escalate
type GateOutcome struct {
	Id      string
	Subject TrustClass
	Passed  bool
	Verdict Verdict
}

// kw: eval result verdict sinks gates events fault
type EvalResult struct {
	Verdict Verdict
	Sinks   []SinkOutcome
	Gates   []GateOutcome
	Events  []ReleaseEvent
	// Authorized is the ordered sequence of calls this recipe cleared, in source order.
	// It is EMPTY unless the recipe reached Allow: a denied or faulted walk authorizes
	// nothing. The executor may run these and only these.
	Authorized []AuthorizedCall
	Fault      string // "" = none; else fail-closed structural halt (inv 8/10)
}

// kw: eval recipe path walk forward-only compose kernel invariant foreach single-arg
func Eval(r Recipe, proposal string, recipeHash string) EvalResult {
	// single input: every `propose` binds the one proposal (backward-compatible).
	return evalWith(r, func(string) string { return proposal }, recipeHash)
}

// EvalArgs gates over SEVERAL named inputs: each `propose out: X` binds the untrusted value
// args[X]. This lets one recipe decide from multiple arguments of a tool call (e.g. namespace
// AND replicas), not just one. An absent key binds "" (which fails a rule — fail closed).
// kw: eval multi-arg named inputs propose-by-name
func EvalArgs(r Recipe, args map[string]string, recipeHash string) EvalResult {
	return evalWith(r, func(out string) string { return args[out] }, recipeHash)
}

// evalWith is the shared core: bind(out) supplies the untrusted value for each propose's
// out-slot (constant proposal for Eval; per-name for EvalArgs).
func evalWith(r Recipe, bind func(string) string, recipeHash string) EvalResult {
	slots := make(map[string]Slot, len(r.Ingredients))
	for k, v := range r.Ingredients {
		slots[k] = v
	}
	idx := make(map[string]int, len(r.Steps)) // ids by first occurrence
	for i, s := range r.Steps {
		if _, seen := idx[s.Id]; !seen {
			idx[s.Id] = i
		}
	}
	res, verdicts := walk(r, idx, slots, bind, recipeHash, 0, 0, 0)
	res.Verdict = gate.AndAll(verdicts...)
	// An authorization is only an authorization if the WHOLE recipe cleared. A later step
	// that denies, escalates or faults retracts every call an earlier step authorized —
	// the executor is handed nothing it may run. Fail closed (inv 8).
	if res.Verdict != Allow || res.Fault != "" {
		res.Authorized = nil
	}
	return res
}

// sortedArgs orders an invoke's argument names so its crossings are recorded deterministically
// (Go map iteration is randomized; the audit must not be).
// kw: sorted argument names deterministic audit invoke
func sortedArgs(m map[string]ArgRule) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// sortedKeys orders map keys so an invoke's crossings are recorded deterministically
// (Go map iteration is randomized; the audit must not be).
// kw: sorted keys deterministic map iteration audit
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// walk walks the recipe graph from step `start` to a terminal, returning the
// accumulated outcomes and per-step verdicts (the caller folds them with AndAll).
// depth>0 means we are inside a foreach body (nesting is refused); elem is the
// foreach iteration ordinal, folded into ReleaseEvent.Ordering so each element's
// crossing is distinct. At the top level elem is 0, so a non-foreach recipe is
// byte-identical to before the refactor (Ordering == the step index).
func walk(r Recipe, idx map[string]int, slots map[string]Slot, bind func(string) string, recipeHash string, start, depth int, elem int64) (EvalResult, []Verdict) {
	var res EvalResult
	var verdicts []Verdict
	stepCount := int64(len(r.Steps))
	// hop: "" = fall-through; else a known, strictly-forward id
	hop := func(i int, target string) (int, bool) {
		if target == "" {
			return i + 1, true
		}
		j, ok := idx[target]
		if !ok || j <= i {
			return 0, false
		}
		return j, true
	}
	fault := func(reason string) {
		res.Fault = reason
		verdicts = append(verdicts, Deny) // fail closed (inv 8/10)
	}
	i := start
walk:
	for i < len(r.Steps) {
		step := r.Steps[i]
		switch step.Kind {
		case NodePropose:
			// the agent's output is untrusted-until-gated; bind(out) is the value for
			// this out-slot (the single proposal, or the named arg for a multi-arg call).
			slots[step.Out] = Slot{Value: bind(step.Out), Class: Untrusted, Origin: "propose"}
			n, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			i = n
		case NodeSink:
			// the crossing gate: refuses the crossing, never the movement
			s, ok := slots[step.In]
			if !ok {
				s = Slot{Class: TrustClass(-1)} // missing slot: severed label, fails closed
			}
			released := ok && step.Rule != nil && step.Rule.Release(s.Value) // a missing slot never releases
			v := gate.GateSink(s.Class, step.Sensitivity, released)
			res.Sinks = append(res.Sinks, SinkOutcome{Field: step.Field, Subject: s.Class, Sink: step.Sensitivity, Released: released, Verdict: v})
			verdicts = append(verdicts, v)
			// structural: the same step that clears the crossing records it (inv 2)
			if step.Sensitivity == SinkAuthoritative && s.Class != Authoritative && released {
				res.Events = append(res.Events, ReleaseEvent{
					SubjectClass: s.Class, SubjectOrigin: s.Origin, CollectedField: step.In,
					TargetClass: Authoritative, TargetField: step.Field,
					AuthorizingRule: step.RuleID, Actor: step.Actor,
					Ordering:   elem*stepCount + int64(i), // per-element ordinal (elem 0 => step index)
					RecipeHash: recipeHash,
				})
			}
			n, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			i = n
		case NodeGate:
			// the checkpoint: guards the movement; halts the path on failure
			s, present := slots[step.In]
			subj := s.Class
			if !present {
				subj = TrustClass(-1) // severed
			}
			if present && step.Rule != nil && step.Rule.Release(s.Value) {
				res.Gates = append(res.Gates, GateOutcome{Id: step.Id, Subject: subj, Passed: true, Verdict: Allow})
				verdicts = append(verdicts, Allow)
				n, ok := hop(i, step.Goto)
				if !ok {
					fault("edge " + step.Id)
					break walk
				}
				i = n
				continue
			}
			v := Deny // severed slot or absent rule always Deny (inv 8)
			if present && step.Rule != nil && step.Escalate {
				v = Escalate // declared on-fail, genuine predicate failure only
			}
			res.Gates = append(res.Gates, GateOutcome{Id: step.Id, Subject: subj, Passed: false, Verdict: v})
			verdicts = append(verdicts, v)
			break walk // halt
		case NodeBranch:
			// routing, never enforcement; edges are always explicit
			s, present := slots[step.In]
			if !present {
				fault("branch " + step.Id) // routing on uncertainty refused
				break walk
			}
			target := step.Default
			for _, c := range step.Cases {
				if c.Rule != nil && c.Rule.Release(s.Value) {
					target = c.Goto
					break
				}
			}
			j, ok := idx[target]
			if target == "" || !ok || j <= i {
				fault("branch " + step.Id)
				break walk
			}
			i = j
		case NodeForeach:
			// bounded fan-out: gate EACH element of a runtime list (inv 13 cap).
			if depth > 0 {
				fault("nested foreach " + step.Id) // no nesting in v1
				break walk
			}
			s, ok := slots[step.In]
			if !ok {
				fault("foreach severed slot " + step.Id) // fail closed
				break walk
			}
			var elems []string
			if err := json.Unmarshal([]byte(s.Value), &elems); err != nil {
				fault("foreach: not a JSON string array " + step.Id)
				break walk
			}
			if len(elems) > foreachCap {
				fault("foreach: over cap " + step.Id) // author-unraisable bound
				break walk
			}
			body, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			for k, e := range elems {
				// each element enters the body fresh and untrusted (declassifying boundary)
				slots[step.As] = Slot{Value: e, Class: Untrusted, Origin: "foreach"}
				inner, innerV := walk(r, idx, slots, bind, recipeHash, body, depth+1, int64(k))
				res.Sinks = append(res.Sinks, inner.Sinks...)
				res.Gates = append(res.Gates, inner.Gates...)
				res.Events = append(res.Events, inner.Events...)
				verdicts = append(verdicts, innerV...) // AndAll'd by the caller: one deny denies the batch
				if inner.Fault != "" && res.Fault == "" {
					res.Fault = inner.Fault
				}
			}
			break walk // foreach is a tail construct: it consumed the rest of the path
		case NodeInvoke, NodeAwait:
			// AUTHORIZATION, not transport: the kernel never calls out. Eval resolves the
			// call's arguments from slots, clears each exactly as an authoritative sink
			// does (the step that clears the crossing records it, inv 2), and appends an
			// AuthorizedCall the executor must re-cross. Eval stays a pure function of its
			// inputs, so an auditor can replay the authorization offline.
			//
			// Refused inside a foreach: that is the ONE construct where an attacker-chosen
			// list length multiplies author-written calls. Everywhere else the number of
			// authorized calls is fixed by the recipe source.
			if depth > 0 {
				fault(step.Kind.String() + " inside foreach " + step.Id)
				break walk
			}
			if step.Tool == "" || len(step.ArgRules) == 0 {
				fault("invoke " + step.Id) // no tool or no arguments: fail closed (inv 8)
				break walk
			}
			if step.Kind == NodeAwait {
				// An await with no condition is not an await: it would degenerate into an
				// unconditional poll that always "succeeds". Fail closed.
				if step.Until == nil {
					fault("await without a condition " + step.Id)
					break walk
				}
				// The bounds are the KERNEL's. Over the cap is a fault, never a clamp: an author
				// who asked for more must be told, not quietly given less.
				if step.Attempts < 1 || step.Attempts > awaitAttemptCap ||
					step.DelayMS < 0 || step.DelayMS > awaitDelayCapMS ||
					step.Attempts*step.DelayMS > awaitTotalCapMS {
					fault("await bounds " + step.Id)
					break walk
				}
			}
			resolved := make(map[string]string, len(step.ArgRules))
			var pending []ReleaseEvent
			ok := true
			// argument names in sorted order, so the crossings a call records are
			// deterministic regardless of map iteration order.
			for _, arg := range sortedArgs(step.ArgRules) {
				ar := step.ArgRules[arg]
				s, present := slots[ar.Slot]
				subj := s.Class
				if !present {
					subj = TrustClass(-1) // severed label, fails closed
				}
				// EACH argument is cleared by ITS OWN rule. A nil rule never clears:
				// an argument nobody wrote a rule for is not thereby permitted.
				released := present && ar.Rule != nil && ar.Rule.Release(s.Value)
				v := gate.GateSink(subj, SinkAuthoritative, released)
				res.Sinks = append(res.Sinks, SinkOutcome{Field: step.Tool + "." + arg, Subject: subj, Sink: SinkAuthoritative, Released: released, Verdict: v})
				verdicts = append(verdicts, v)
				if !released {
					ok = false
					continue
				}
				resolved[arg] = s.Value
				if subj != Authoritative {
					// buffered, not recorded yet: a call is all-or-nothing, so an argument
					// that cleared while a SIBLING failed must not leave a crossing behind.
					// The record states what happened, not what merely evaluated.
					pending = append(pending, ReleaseEvent{
						SubjectClass: subj, SubjectOrigin: s.Origin, CollectedField: ar.Slot,
						TargetClass: Authoritative, TargetField: step.Tool + "." + arg,
						AuthorizingRule: ar.RuleID, Actor: step.Actor,
						Ordering:   elem*stepCount + int64(i),
						RecipeHash: recipeHash,
					})
				}
			}
			// all-or-nothing per call: one unreleased argument authorizes no call at all.
			// A partially-cleared call is exactly the hole the coverage contract closes.
			if ok {
				res.Events = append(res.Events, pending...) // the call happens: its crossings are real
				ac := AuthorizedCall{
					StepID: step.Id, Tool: step.Tool, Args: resolved,
					Ordinal: elem*stepCount + int64(i),
				}
				if step.Kind == NodeAwait {
					ac.Until, ac.UntilID = step.Until, step.UntilID
					ac.Attempts, ac.DelayMS = step.Attempts, step.DelayMS
				}
				res.Authorized = append(res.Authorized, ac)
			}
			n, ok2 := hop(i, step.Goto)
			if !ok2 {
				fault("edge " + step.Id)
				break walk
			}
			i = n
		case NodeExit:
			break walk // explicit terminal: halt the path, add no verdict and no crossing
		default:
			fault("kind " + step.Id) // complete mediation (inv 10)
			break walk
		}
	}
	return res, verdicts
}
