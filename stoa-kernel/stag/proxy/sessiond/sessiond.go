// Package sessiond is the stag-proxy v2 daemon surface: a standing HTTP server where each MCP
// session is bound to a dispatcher-chosen recipe (Planning/24 v2, /25). The TRUSTED dispatcher
// POSTs /sessions to bind a session to a set of routes and gets back an opaque token; the UNTRUSTED
// agent connects to /mcp/<token>, and every tool call in that session is gated by THAT session's
// recipe — not a global table. The agent cannot choose its own recipe (the token is minted here and
// the binding is server-side). One daemon owns one downstream + one audit sink, so there is no
// per-run log fork.
package sessiond

// file-kw: session daemon registry token router session-to-recipe streamable-http bind fail-closed no-fork

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/router"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sessionIdleTimeout closes an MCP session (its streamable-HTTP transport) after this long with no
// client request, so a standing daemon does not accumulate abandoned protocol sessions. The token→
// recipe binding in the Registry is separate and ephemeral (cleared on daemon restart); per-token
// TTL is a v1.1 hardening.
const sessionIdleTimeout = 30 * time.Minute

// boundSession is one session's binding: the recipe router (ACT channel), the context providers (READ
// channel), and the per-session crossing budget. All are chosen by the trusted dispatcher at bind time;
// the untrusted agent gets only the token.
//
// The budget lives HERE, on the token binding — not in the per-MCP-session gating server — because the
// untrusted agent can re-initialize the MCP transport at will (a fresh gating server each time). One
// *proxy.CrossingBudget per token, shared across every gating server the agent opens under that token,
// is what makes the cap N durable against reconnection (Planning/34 §6.2).
type boundSession struct {
	router    proxy.Router
	providers []provider.ContextProvider
	budget    *proxy.CrossingBudget
}

// Registry holds active session bindings — each a boundSession (the recipe router the dispatcher
// chose, plus its READ-channel providers). In-memory and EPHEMERAL (v1): a session dies with the
// daemon; a dropped session just re-dispatches. This is the Session entity of Planning/25.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]boundSession
}

// NewRegistry returns an empty session registry.
func NewRegistry() *Registry { return &Registry{sessions: map[string]boundSession{}} }

// Create builds a session router from route specs (fail-closed: it needs at least one route that
// resolves) and binds it — with its READ-channel providers — under a fresh opaque token. The recipe
// and provider choice belong to the caller (the trusted dispatcher); the untrusted agent only ever
// receives the token.
func (r *Registry) Create(specs []router.Spec, providers []provider.ContextProvider, loadRecipe func(string) ([]byte, error), fleet mcpgate.Fleet, requireBounded bool, crossingBudget int) (string, []router.RouteError, error) {
	resolved := router.BuildStrict(specs, loadRecipe, requireBounded)
	// Leakage warnings are non-fatal (the route bound) but the operator is accepting an unbounded channel
	// — make it visible. In strict mode the same condition is instead a route error, returned below.
	for _, w := range resolved.Warnings {
		log.Printf("session bind: route %q -> recipe %q binds with UNBOUNDED leakage: %s (start with -require-bounded to refuse)", w.Tool, w.Recipe, w.Err)
	}

	// THE ROUTE DELEGATES. Each route names the server that serves its tool; resolve it here, at bind,
	// so a route the gate cannot actually dispatch is rejected WITH ITS REASON rather than binding
	// cleanly and failing at call time. The gate never guesses a server from a tool name — a route must
	// mean the same thing tomorrow, when another server exposing that name has been registered.
	// adv is the ADVERTISED name (<server>__<tool>) — the Router key. rt.Tool is the tool's name on the
	// downstream, which is what the fleet knows it by; looking it up under the advertised name would ask
	// the server for a tool it has never heard of.
	for adv, rt := range resolved.Router {
		if rt.Server == "" {
			delete(resolved.Router, adv)
			resolved.Errors = append(resolved.Errors, router.RouteError{Tool: rt.Tool, Server: rt.Server,
				Err: "route names no MCP server — set `server` so the gate knows where to dispatch it"})
			continue
		}
		if _, _, err := fleet.Lookup(rt.Server, rt.Tool); err != nil {
			delete(resolved.Router, adv) // fail closed: undispatchable => ungoverned => not served
			resolved.Errors = append(resolved.Errors, router.RouteError{Tool: rt.Tool, Server: rt.Server, Err: err.Error()})
		}
	}

	if len(resolved.Router) == 0 {
		return "", resolved.Errors, errors.New("no valid routes in binding")
	}
	tok, err := mintToken()
	if err != nil {
		return "", nil, err
	}
	r.mu.Lock()
	// One budget per token, created here and shared across every gating server this token opens — so the
	// agent cannot reset the cap N by reconnecting the MCP transport.
	r.sessions[tok] = boundSession{router: resolved.Router, providers: providers, budget: proxy.NewCrossingBudget(crossingBudget)}
	r.mu.Unlock()
	return tok, resolved.Errors, nil
}

// lookup resolves a token to its session binding.
func (r *Registry) lookup(tok string) (boundSession, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bs, ok := r.sessions[tok]
	return bs, ok
}

// Count reports the number of live sessions (for /health and tests).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func mintToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Deps are the per-daemon gate ingredients shared across every session — everything EXCEPT the
// per-session Routes: the egress sink (the one owned audit log), the approval store + escalation
// hook (Stage 5), and the shared downstream to forward cleared calls to.
type Deps struct {
	Sink       proxy.Sink
	Approvals  proxy.Approvals
	OnEscalate func(ctx context.Context, n proxy.PendingNotice)
	// Fleet is EVERY connected downstream, indexed by the tool each one owns. The gate fronts several
	// tool servers at once and the route decides which one a cleared call reaches.
	Fleet      mcpgate.Fleet
	LoadRecipe func(string) ([]byte, error)
	// RecordRead audits one READ crossing (Planning/30). May be nil (recording best-effort). The
	// READ channel is label+record, so this is the "record" half; it is separate from Sink (the
	// hash-chained ACT-release log) because a read is not a release.
	RecordRead func(ctx context.Context, ev provider.ReadEvent)
	// Auth guards POST /sessions with the `dispatch` role (Planning/31): binding a session CHOOSES
	// the recipe that will govern it, so an unauthenticated binder could simply pick the most
	// permissive recipe — the "the agent cannot choose its own recipe" invariant would collapse.
	// A NIL Auth fails CLOSED. Note /mcp/<token> is deliberately NOT guarded by this: the opaque
	// session token IS the agent's credential, and handing the untrusted agent a control-plane
	// bearer would be exactly backwards.
	Auth *auth.Authenticator
	// CrossingBudget is the per-session forwarded-crossing cap N enforced at the gate (Planning/34 §6.2);
	// 0 = unlimited. RequireBounded makes bind REFUSE any recipe with unbounded leakage (§6.1) instead of
	// binding it with a warning — the high-assurance posture where the whole deployment keeps a
	// computable per-session leakage ceiling. Both default off (zero value) so existing deployments are
	// unchanged until an operator opts in.
	CrossingBudget int
	RequireBounded bool
}

// Handler is the daemon's HTTP surface:
//   - POST /sessions  (TRUSTED — the dispatcher) binds a session to routes, returns {token, path}.
//   - /mcp/<token>    (UNTRUSTED — the agent) is the gated MCP endpoint; the token selects the
//     session's recipe. An unknown/absent token returns 400 (fail closed — no session, no gate).
func Handler(reg *Registry, deps Deps) http.Handler {
	mux := http.NewServeMux()

	// POST /sessions is the TRUSTED binder — it chooses the recipe. `dispatch` role required.
	mux.HandleFunc("POST /sessions", deps.Auth.Guard(auth.RoleDispatch)(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Routes []struct {
				Tool    string `json:"tool"`
				Server  string `json:"server"` // WHICH MCP server serves it. The route delegates; the gate never infers.
				Recipe  string `json:"recipe"`
				GateArg string `json:"gateArg"`
			} `json:"routes"`
			// Context is the READ-channel binding (Planning/30): the provider specs (already resolved
			// upstream from the config DB) this session may read. Optional — absent => no READ channel.
			Context []struct {
				Name   string `json:"name"`
				Kind   string `json:"kind"`
				Config string `json:"config"`
			} `json:"context"`
		}
		body, _ := io.ReadAll(r.Body)
		if json.Unmarshal(body, &req) != nil || len(req.Routes) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "need routes:[{tool,server,recipe,gateArg}]"})
			return
		}
		specs := make([]router.Spec, 0, len(req.Routes))
		for _, rt := range req.Routes {
			specs = append(specs, router.Spec{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg})
		}
		// Build the READ-channel providers. A provider that won't build (unsupported kind, bad config)
		// is DROPPED from the session and logged — fail closed, never fabricate a source.
		providers := make([]provider.ContextProvider, 0, len(req.Context))
		for _, c := range req.Context {
			var p provider.ContextProvider
			var perr error
			// mcp_resource needs a LIVE downstream session, which only the fleet holds — so it is
			// resolved here (not in the MCP-free provider.FromConfig), preserving the quarantine.
			if c.Kind == "mcp_resource" {
				p, perr = mcpgate.NewMCPResourceProvider(deps.Fleet, c.Name, c.Config)
			} else {
				p, perr = provider.FromConfig(c.Name, c.Kind, c.Config)
			}
			if perr != nil {
				log.Printf("session bind: dropping context provider %q: %v", c.Name, perr)
				continue
			}
			providers = append(providers, p)
		}
		tok, rerrs, err := reg.Create(specs, providers, deps.LoadRecipe, deps.Fleet, deps.RequireBounded, deps.CrossingBudget)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "routeErrors": routeErrView(rerrs)})
			return
		}
		// A PARTIAL binding must say so. Some routes can be dropped while others bind — a tool no
		// connected server exposes, or one two servers contest — and returning a clean 200 would tell the
		// dispatcher it got everything it asked for. It would then hand the agent a task needing a tool
		// the agent was never given, and the failure would surface as confused model behaviour rather
		// than as the configuration error it is.
		out := map[string]any{"token": tok, "path": "/mcp/" + tok}
		if len(rerrs) > 0 {
			out["routeErrors"] = routeErrView(rerrs)
		}
		writeJSON(w, http.StatusOK, out)
	}))

	// One StreamableHTTPHandler serves all sessions; getServer is called once per NEW MCP session
	// and returns the gating server bound to THAT token's recipe. NO control-plane bearer here: the
	// opaque session token in the path IS the untrusted agent's credential (Planning/31).
	streamable := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		tok := strings.TrimPrefix(req.URL.Path, "/mcp/")
		bs, ok := reg.lookup(tok)
		if !ok {
			return nil // -> 400: no binding, no gate, nothing served
		}
		// bs.budget is the token's ONE shared counter — every MCP session the agent opens under this token
		// draws down the same N, so reconnecting cannot reset it.
		gate := proxy.Gate{Routes: bs.router, Sink: deps.Sink, Approvals: deps.Approvals, OnEscalate: deps.OnEscalate, Budget: bs.budget}
		read := mcpgate.ReadChannel{Providers: bs.providers, Record: deps.RecordRead}
		return mcpgate.NewGatingServer(gate, deps.Fleet, read)
	}, &mcp.StreamableHTTPOptions{SessionTimeout: sessionIdleTimeout})
	mux.Handle("/mcp/", streamable)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions": reg.Count()})
	})
	return mux
}

func routeErrView(errs []router.RouteError) []map[string]string {
	out := make([]map[string]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, map[string]string{"tool": e.Tool, "recipe": e.Recipe, "error": e.Err})
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
