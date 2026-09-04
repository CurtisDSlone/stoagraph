// Package serve is the HTTP operator surface over the gating proxy (Planning/16):
// the backend the Next.js console talks to. It wraps a proxy.Gate in a thin,
// fail-closed JSON HTTP layer — POST /api/decide gates a submitted tool call and
// returns a legible DecisionView; GET /api/log is the signed audit view; policies
// and health round it out. The gate is invoked only for a well-formed request.
package serve

// file-kw: http api console proxy gate decide log policies health fail-closed json cors no-auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/notify"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/router"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// kw: server gate logpath pub priv policies recipes store approval-webhook
type Server struct {
	Gate     proxy.Gate
	LogPath  string
	Pub      ed25519.PublicKey
	Priv     ed25519.PrivateKey // approval signing key: mints the signed release on approve (Stage 5)
	Policies []PolicyView
	Recipes  recipestore.Store // the recipe-authoring store (admin console)
	Store    *store.Store      // the config store; when set, the gate is driven by its route table
	// Auth guards the control plane (Planning/31). A NIL Auth fails CLOSED — every guarded route
	// 401s — so a misconfigured deploy is locked, never wide open.
	Auth *auth.Authenticator
	// ApprovalWebhook, if set, is POSTed a PendingNotice when the gate escalates a fresh action.
	ApprovalWebhook string
	// Discover connects to a downstream MCP server (with its configured auth) and lists its tools
	// (injected by the cmd over the quarantined MCP SDK; nil = discovery disabled). Takes the whole
	// server so the credential travels with it. Keeping it a func keeps serve free of the MCP dep.
	Discover func(ctx context.Context, srv store.MCPServer) ([]store.MCPTool, error)
	// OAuth is the per-server token store for oauth-scheme downstreams; PublicURL is this server's
	// externally-reachable base (the OAuth redirect_uri is PublicURL + oauth.CallbackPath). The human
	// operator runs sign-in here; the gate holds the tokens so the agent never does.
	OAuth     oauth.Store
	PublicURL string
	// oauthPending tracks in-flight sign-ins (state -> PKCE verifier + discovered config) between
	// /api/oauth/start and the browser callback. In-memory: a restart mid-flow just means re-clicking.
	oauthMu      sync.Mutex
	oauthPending map[string]pendingOAuth
}

// liveGate returns the gate to decide with: when a Store is configured, the router
// is resolved FRESH from the route table (so a route added in the console takes
// effect immediately), keeping the egress Sink from the static Gate. A store/list
// error yields an empty router — every tool unrouted, i.e. denied (fail closed).
func (s *Server) liveGate(r *http.Request) proxy.Gate {
	if s.Store == nil {
		return s.Gate
	}
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		return proxy.Gate{Routes: proxy.Router{}, Sink: s.Gate.Sink, Approvals: s.Store, OnEscalate: notify.Webhook(s.ApprovalWebhook)}
	}
	specs := make([]router.Spec, 0, len(routes))
	for _, rt := range routes {
		// Sequenced MUST be carried — see the same note in cmd/stag-proxy. Dropping it here makes
		// the live gate advertise and freely accept tools the store marks grant-only.
		specs = append(specs, router.Spec{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg, Sequenced: rt.Sequenced})
	}
	resolved := router.Build(specs, s.Recipes.Get)
	// The live gate carries the approval store (Stage 5): an escalate on an approval-gated recipe
	// records a pending row + fires the webhook; an approved retry releases.
	return proxy.Gate{Routes: resolved.Router, Sink: s.Gate.Sink, Approvals: s.Store, OnEscalate: notify.Webhook(s.ApprovalWebhook)}
}

// kw: policy view tool recipe gatearg
type PolicyView struct {
	Tool    string `json:"tool"`
	Recipe  string `json:"recipe"`
	GateArg string `json:"gateArg"`
}

// kw: chain view sense reason decide act prove
type ChainView struct {
	Sense  string `json:"sense"`
	Reason string `json:"reason"`
	Decide string `json:"decide"`
	Act    string `json:"act"`
	Prove  string `json:"prove"`
}

// kw: event view field rule actor subject
type EventView struct {
	Field   string `json:"field"`
	Rule    string `json:"rule"`
	Actor   string `json:"actor"`
	Subject string `json:"subject"`
}

// kw: decision view verdict forward value rule chain events
type DecisionView struct {
	Tool         string      `json:"tool"`
	Verdict      string      `json:"verdict"`
	Forward      bool        `json:"forward"`
	Value        string      `json:"value"`
	RuleFired    string      `json:"ruleFired,omitempty"`
	SubjectClass string      `json:"subjectClass"`
	Chain        ChainView   `json:"chain"`
	Events       []EventView `json:"events,omitempty"`
	Fault        string      `json:"fault,omitempty"`
	ApprovalID   string      `json:"approvalId,omitempty"` // set when an escalate awaits/holds a human approval
}

// RecordView is one leaf of the audit chain: a decision the gate made. EVERY decision is recorded —
// allow, deny and escalate alike — because a blocked attempt is the evidence that the control worked.
// Releases are the crossings that ACTUALLY happened, so they are present only when Forwarded is true.
// (Distinct from DecisionView above, which is the /api/decide RESPONSE, not an audit leaf.)
// kw: record view audit leaf tool verdict forwarded value recipe fault releases
type RecordView struct {
	Tool      string      `json:"tool"`
	Verdict   string      `json:"verdict"` // allow | deny | escalate
	Forwarded bool        `json:"forwarded"`
	Value     string      `json:"value"`
	Recipe    string      `json:"recipe,omitempty"`
	Fault     string      `json:"fault,omitempty"`
	Releases  []EventView `json:"releases,omitempty"`
}

// kw: verify view count head signed keyid verified error
type VerifyView struct {
	Count    int64  `json:"count"`
	Head     string `json:"head"`
	Signed   bool   `json:"signed"`
	KeyID    string `json:"keyId,omitempty"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// kw: log view decisions verify audit-chain
type LogView struct {
	Records []RecordView `json:"records"`
	Verify  VerifyView   `json:"verify"`
}

// kw: handler mux routes api decide log policies health cors
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Planning/31 role map.
	//   read    = any valid control-plane role (the orchestrator must read the catalog + POLL approvals)
	//   admin   = policy CRUD — rewriting a recipe is a total bypass, so it is human-only
	//   approve = mints the ed25519 signed release. HUMAN ONLY: the `dispatch` (orchestrator) token is
	//             deliberately NOT accepted here — an orchestrator that could approve its own
	//             escalations would make the human-in-the-loop gate decorative.
	read := s.Auth.Guard(auth.RoleAdmin, auth.RoleApprove, auth.RoleDispatch)
	admin := s.Auth.Guard(auth.RoleAdmin)
	approve := s.Auth.Guard(auth.RoleApprove)

	mux.HandleFunc("/api/decide", read(s.handleDecide))
	mux.HandleFunc("/api/log", read(s.handleLog))
	mux.HandleFunc("/api/policies", read(s.handlePolicies))
	// Liveness. OPEN (a container probe has no credential). /health is the NORMALIZED path every
	// service in this product answers, so one Docker healthcheck works everywhere; /api/health is
	// kept because the console already calls it.
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/health", s.handleHealth)
	// recipe authoring (admin console) — method+path patterns (Go 1.22+)
	mux.HandleFunc("POST /api/recipes/validate", admin(s.handleRecipeValidate))
	mux.HandleFunc("GET /api/recipes", read(s.handleRecipeList))
	mux.HandleFunc("POST /api/recipes", admin(s.handleRecipeSave))
	mux.HandleFunc("GET /api/recipes/{name}", read(s.handleRecipeGet))
	mux.HandleFunc("DELETE /api/recipes/{name}", admin(s.handleRecipeDelete))
	// routes (tool -> recipe bindings; the multi-tool gate is driven by these)
	mux.HandleFunc("GET /api/routes", read(s.handleRouteList))
	mux.HandleFunc("POST /api/routes", admin(s.handleRoutePut))
	mux.HandleFunc("DELETE /api/routes/{server}/{tool}", admin(s.handleRouteDelete))
	// MCP servers (the ACT channel adapters): add/discover/list/delete downstream servers
	mux.HandleFunc("GET /api/mcp-servers", read(s.handleMCPList))
	mux.HandleFunc("POST /api/mcp-servers", admin(s.handleMCPPut))
	mux.HandleFunc("DELETE /api/mcp-servers/{name}", admin(s.handleMCPDelete))

	// OAuth sign-in for oauth-scheme downstreams. start/status are admin/read-guarded; the callback is
	// PUBLIC because the provider redirects the operator's browser to it — the unguessable state param
	// (minted only by an admin-authenticated start) is what authenticates the completion.
	mux.HandleFunc("POST /api/oauth/start", admin(s.handleOAuthStart))
	mux.HandleFunc("GET /api/oauth/status", read(s.handleOAuthStatus))
	mux.HandleFunc("GET /api/oauth/callback", s.handleOAuthCallback)
	// context providers (the READ channel adapters)
	mux.HandleFunc("GET /api/providers", read(s.handleProviderList))
	mux.HandleFunc("POST /api/providers", admin(s.handleProviderPut))
	mux.HandleFunc("DELETE /api/providers/{name}", admin(s.handleProviderDelete))
	// human-approval queue (Stage 5): GET is a POLL (the orchestrator waits on its own escalation);
	// approve/deny mint the signed release and are HUMAN-ONLY.
	mux.HandleFunc("GET /api/approvals", read(s.handleApprovalList))
	mux.HandleFunc("GET /api/approvals/{id}", read(s.handleApprovalGet))
	mux.HandleFunc("POST /api/approvals/{id}/approve", approve(s.handleApprovalApprove))
	mux.HandleFunc("POST /api/approvals/{id}/deny", approve(s.handleApprovalDeny))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, errObj("not found"))
	})
	return cors(mux)
}

// kw: cors permissive dev preflight
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		// Authorization must be allowed or the console can never present its bearer token (Planning/31).
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// kw: decide decode gate view fail-closed
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errObj("method not allowed"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Tool string            `json:"tool"`
		Args map[string]string `json:"args"`
	}
	if json.Unmarshal(body, &req) != nil || req.Tool == "" {
		writeJSON(w, http.StatusBadRequest, errObj("invalid decide request: need a non-empty tool"))
		return
	}
	dec := s.liveGate(r).Decide(r.Context(), proxy.ToolCall{Tool: req.Tool, Args: req.Args})
	writeJSON(w, http.StatusOK, s.view(dec))
}

// kw: view decision to legible view chain events
func (s *Server) view(d proxy.Decision) DecisionView {
	v := DecisionView{
		Tool:         d.Tool,
		Verdict:      d.Verdict.String(),
		Forward:      d.Forward,
		Value:        d.Value,
		SubjectClass: "untrusted", // the agent's tool call is untrusted-until-gated
		Fault:        d.Fault,
		ApprovalID:   d.ApprovalID,
	}
	for _, ev := range d.Events {
		v.Events = append(v.Events, EventView{
			Field: ev.TargetField, Rule: ev.AuthorizingRule, Actor: ev.Actor, Subject: ev.SubjectClass.String(),
		})
		if v.RuleFired == "" {
			v.RuleFired = ev.AuthorizingRule
		}
	}
	unrouted := strings.HasPrefix(d.Fault, "no recipe")
	v.Chain = ChainView{
		Sense:  "ok",
		Reason: okSkip(!unrouted),
		Decide: v.Verdict,
		Act:    okSkip(d.Forward),
		Prove:  okSkip(len(d.Events) > 0),
	}
	return v
}

// kw: log read verify signed events
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errObj("method not allowed"))
		return
	}
	lv := LogView{}
	b, err := os.ReadFile(s.LogPath)
	if err != nil || len(b) == 0 {
		writeJSON(w, http.StatusOK, lv) // no log yet: empty, not an error
		return
	}
	res, verr := egress.Verify(bytes.NewReader(b))
	if verr != nil {
		lv.Verify.Error = verr.Error()
		writeJSON(w, http.StatusOK, lv)
		return
	}
	// egress.Verify returned no error => the hash chain is INTACT. That is the tamper-evident
	// guarantee, and it holds with or without a signature — so `Verified` reflects it here. A signed
	// checkpoint is a STRONGER, additional property (offline-verifiable against a public key), tracked
	// separately in `Signed`; a signature that FAILS demotes back to unverified with an error.
	lv.Verify.Count, lv.Verify.Head = res.Count, res.Head
	lv.Verify.Verified = true
	if cp, cerr := os.ReadFile(s.LogPath + ".checkpoint"); cerr == nil && s.Pub != nil {
		lv.Verify.Signed = true
		var sc egress.SignedCheckpoint
		if json.Unmarshal(cp, &sc) == nil {
			lv.Verify.KeyID = sc.KeyID
			if _, e := egress.VerifySigned(s.Pub, sc, bytes.NewReader(b)); e != nil {
				lv.Verify.Verified = false
				lv.Verify.Error = e.Error()
			}
		}
	}
	lv.Records = readRecords(b)
	writeJSON(w, http.StatusOK, lv)
}

// kw: read records parse leaves to audit views allow deny escalate releases
func readRecords(b []byte) []RecordView {
	var out []RecordView
	for _, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var lf egress.Leaf
		if json.Unmarshal(line, &lf) != nil {
			continue
		}
		d := lf.Decision
		dv := RecordView{
			Tool: d.Tool, Verdict: d.Verdict, Forwarded: d.Forwarded,
			Value: d.Value, Recipe: d.Recipe, Fault: d.Fault,
		}
		for _, ev := range d.Events { // releases: present only on a forwarded call
			dv.Releases = append(dv.Releases, EventView{
				Field: ev.TargetField, Rule: ev.AuthorizingRule,
				Actor: ev.Actor, Subject: ev.SubjectClass.String(),
			})
		}
		out = append(out, dv)
	}
	return out
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errObj("method not allowed"))
		return
	}
	pols := s.Policies
	if pols == nil {
		pols = []PolicyView{}
	}
	writeJSON(w, http.StatusOK, pols)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func okSkip(ok bool) string {
	if ok {
		return "ok"
	}
	return "skip"
}

func errObj(msg string) map[string]string { return map[string]string{"error": msg} }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
