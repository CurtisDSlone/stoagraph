// Package sessiond is the stag-proxy v2 daemon surface: a standing HTTP server where each MCP
// session is bound to a dispatcher-chosen recipe (Planning/24 v2, /25). The TRUSTED dispatcher
// POSTs /sessions to bind a session to a set of routes and gets back an opaque token; the UNTRUSTED
// agent connects to /mcp/<token>, and every tool call in that session is gated by THAT session's
// recipe — not a global table. The agent cannot choose its own recipe (the token is minted here and
// the binding is server-side). One daemon owns one downstream + one audit sink, so there is no
// per-run log fork.
//
// Bindings are DURABLE and SHARED: they live in the store (proxy.Sessions), so a binding survives a
// daemon restart and any replica of the daemon can serve any token. What each replica keeps for
// itself is only the compiled form of a binding (the resolved router, the built providers), derived
// from the row on first use and never authoritative: existence and the crossing budget are asked of
// the store on every request.
package sessiond

// file-kw: session daemon registry token router session-to-recipe streamable-http bind fail-closed no-fork revoke revocation withdraw-authority binding-vs-transport unknown-token jsonrpc-error rebind durable replicas store-backed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// recipe BINDING is separate: it lives in the store until revoked. A per-binding TTL is still a
// hardening item (rows accumulate until revoked).
const sessionIdleTimeout = 30 * time.Minute

// storeTimeout bounds each store call made on the request path (liveness, budget). A hung database
// must not hang the agent's request forever; it fails closed at this deadline instead.
const storeTimeout = 5 * time.Second

// compiled is the replica-local, derived form of a binding: the recipe router (ACT channel) and the
// built context providers (READ channel). Rebuilt from the row on first use; holds no authority —
// existence and budget are the store's to answer.
type compiled struct {
	router    proxy.Router
	providers []provider.ContextProvider
}

// Registry is the daemon's view of session bindings: a store of Bindings (shared across replicas)
// plus a cache of their compiled forms (this replica only). This is the Session entity of Planning/25.
type Registry struct {
	sessions proxy.Sessions
	mu       sync.Mutex
	cache    map[string]*compiled // binding id -> compiled; evicted on revoke or a failed liveness check
	deps     Deps                 // set by Handler; needed to compile a binding read back from the store
}

// NewRegistry returns a registry over an in-memory Sessions: bindings die with the process and are
// invisible to other replicas. It is what tests and single-process embedders use; the daemon uses
// NewRegistryWith(store).
func NewRegistry() *Registry { return NewRegistryWith(NewMemorySessions()) }

// NewRegistryWith returns a registry over the given Sessions (the config store in the daemon).
func NewRegistryWith(s proxy.Sessions) *Registry {
	return &Registry{sessions: s, cache: map[string]*compiled{}}
}

// Create binds a session: it snapshots the source of every recipe the routes name, compiles the
// binding (fail-closed: it needs at least one route that resolves AND is dispatchable), persists it
// under the digest of a fresh opaque token, and returns the token. The recipe and provider choice
// belong to the caller (the trusted dispatcher); the untrusted agent only ever receives the token.
func (r *Registry) Create(ctx context.Context, routes []proxy.BindingRoute, providers []proxy.BindingProvider) (string, []router.RouteError, error) {
	// Snapshot FIRST: the binding must carry the text it was compiled from, so a replica that reads
	// it back compiles the same policy the binder did. Load errors are left out of the snapshot and
	// surface below as route errors with the loader's own message.
	sources := map[string]string{}
	loadErr := map[string]error{}
	for _, rt := range routes {
		if _, seen := sources[rt.Recipe]; seen {
			continue
		}
		if _, failed := loadErr[rt.Recipe]; failed {
			continue
		}
		src, err := r.deps.LoadRecipe(rt.Recipe)
		if err != nil {
			loadErr[rt.Recipe] = err
			continue
		}
		sources[rt.Recipe] = string(src)
	}
	b := proxy.Binding{Routes: routes, Providers: providers, Recipes: sources, Budget: r.deps.CrossingBudget}
	c, rerrs := r.compile(b, func(name string) ([]byte, error) {
		if src, ok := sources[name]; ok {
			return []byte(src), nil
		}
		if err, ok := loadErr[name]; ok {
			return nil, err
		}
		return nil, fmt.Errorf("recipe %q not in binding", name)
	})
	if len(c.router) == 0 {
		return "", rerrs, errors.New("no valid routes in binding")
	}

	tok, err := mintToken()
	if err != nil {
		return "", nil, err
	}
	b.ID = proxy.SessionID(tok)
	if err := r.sessions.PutBinding(ctx, b); err != nil {
		return "", nil, fmt.Errorf("persist binding: %w", err)
	}
	r.mu.Lock()
	r.cache[b.ID] = c
	r.mu.Unlock()
	return tok, rerrs, nil
}

// compile turns a binding into its router + providers, with the same fail-closed rules at bind and at
// rehydration: a route must resolve to a recipe AND name a server the fleet can dispatch to.
func (r *Registry) compile(b proxy.Binding, load func(string) ([]byte, error)) (*compiled, []router.RouteError) {
	specs := make([]router.Spec, 0, len(b.Routes))
	for _, rt := range b.Routes {
		specs = append(specs, router.Spec{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg, Sequenced: rt.Sequenced})
	}
	resolved := router.BuildStrict(specs, load, r.deps.RequireBounded)
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
		if _, _, err := r.deps.Fleet.Lookup(rt.Server, rt.Tool); err != nil {
			delete(resolved.Router, adv) // fail closed: undispatchable => ungoverned => not served
			resolved.Errors = append(resolved.Errors, router.RouteError{Tool: rt.Tool, Server: rt.Server, Err: err.Error()})
		}
	}
	// Build the READ-channel providers. A provider that won't build (unsupported kind, bad config)
	// is DROPPED from the session and logged — fail closed, never fabricate a source.
	providers := make([]provider.ContextProvider, 0, len(b.Providers))
	for _, ps := range b.Providers {
		var p provider.ContextProvider
		var perr error
		// mcp_resource needs a LIVE downstream session, which only the fleet holds — so it is
		// resolved here (not in the MCP-free provider.FromConfig), preserving the quarantine.
		if ps.Kind == "mcp_resource" {
			p, perr = mcpgate.NewMCPResourceProvider(r.deps.Fleet, ps.Name, ps.Config)
		} else {
			p, perr = provider.FromConfig(ps.Name, ps.Kind, ps.Config)
		}
		if perr != nil {
			log.Printf("session bind: dropping context provider %q: %v", ps.Name, perr)
			continue
		}
		providers = append(providers, p)
	}
	return &compiled{router: resolved.Router, providers: providers}, resolved.Errors
}

// kw: revoke session binding withdraw authority running-agent only-way disarm
// Revoke drops a session binding, so the token stops resolving on EVERY replica and the agent holding
// it is served nothing (an unknown token fails closed at /mcp/<token>: no binding, no gate).
//
// Revocation is the ONLY way to withdraw authority from a running agent. A binding holds a COMPILED
// copy of its recipes, so deleting the recipe or the route from the registry does not disarm it —
// the registry and the enforcement path diverge, and an operator reading an empty route table would
// wrongly conclude nothing can be called. Revoking the token is what actually closes the gate.
//
// It reports whether a binding was removed, so a caller can tell a revoke from a no-op.
func (r *Registry) Revoke(ctx context.Context, tok string) bool {
	id := proxy.SessionID(tok)
	removed, err := r.sessions.DeleteBinding(ctx, id)
	if err != nil {
		log.Printf("session revoke %s: store error: %v", id, err)
	}
	r.mu.Lock()
	delete(r.cache, id)
	r.mu.Unlock()
	return removed
}

// lookup resolves a token to its compiled binding. The store is asked whether the binding exists on
// EVERY call — that is what makes a revoke on one replica reach an agent connected to another — and
// the compiled form is cached per replica because compiling is pure and the row is the truth.
func (r *Registry) lookup(ctx context.Context, tok string) (*compiled, bool) {
	id := proxy.SessionID(tok)
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	r.mu.Lock()
	c, cached := r.cache[id]
	r.mu.Unlock()
	if cached {
		live, err := r.sessions.HasBinding(ctx, id)
		if err != nil {
			log.Printf("session %s: liveness check failed, refusing (fail closed): %v", id, err)
			return nil, false
		}
		if !live {
			r.mu.Lock()
			delete(r.cache, id)
			r.mu.Unlock()
			return nil, false
		}
		return c, true
	}

	b, ok, err := r.sessions.GetBinding(ctx, id)
	if err != nil {
		log.Printf("session %s: load failed, refusing (fail closed): %v", id, err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	// Rehydrate: this replica has never served this token. Compile from the SNAPSHOT the binder
	// stored, never from this replica's recipe directory, so the agent meets the same policy here.
	c, rerrs := r.compile(b, func(name string) ([]byte, error) {
		if src, ok := b.Recipes[name]; ok {
			return []byte(src), nil
		}
		return nil, fmt.Errorf("recipe %q missing from binding snapshot", name)
	})
	for _, e := range rerrs {
		log.Printf("session %s: rehydrated route %q -> %q unresolved on this replica: %s", id, e.Tool, e.Recipe, e.Err)
	}
	if len(c.router) == 0 {
		log.Printf("session %s: no route is dispatchable on this replica, refusing", id)
		return nil, false
	}
	r.mu.Lock()
	r.cache[id] = c
	r.mu.Unlock()
	return c, true
}

// live is Gate.Live for a token: does the binding still exist, asked of the store now.
func (r *Registry) live(tok string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	ok, err := r.sessions.HasBinding(ctx, proxy.SessionID(tok))
	if err != nil {
		log.Printf("session liveness check failed, treating as revoked (fail closed): %v", err)
		return false
	}
	return ok
}

// Count reports the number of live bindings (for /health and tests).
func (r *Registry) Count(ctx context.Context) int {
	n, err := r.sessions.CountBindings(ctx)
	if err != nil {
		return -1
	}
	return n
}

// budget returns the token's Budget: one shared counter in the store, drawn down by every gating
// server on every replica that serves this token. limit <= 0 never touches the store.
func (r *Registry) budget(tok string, limit int) proxy.Budget {
	return &storedBudget{sessions: r.sessions, id: proxy.SessionID(tok), limit: limit}
}

// storedBudget is the daemon's proxy.Budget: Reserve is one atomic UPDATE in the store. A store
// error is a refusal, not a free crossing.
type storedBudget struct {
	sessions proxy.Sessions
	id       string
	limit    int
}

func (b *storedBudget) Reserve() bool {
	if b.limit <= 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	ok, err := b.sessions.ReserveCrossing(ctx, b.id)
	if err != nil {
		log.Printf("session %s: budget reserve failed, refusing (fail closed): %v", b.id, err)
		return false
	}
	return ok
}

func (b *storedBudget) Release() {
	if b.limit <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := b.sessions.ReleaseCrossing(ctx, b.id); err != nil {
		log.Printf("session %s: budget release failed: %v", b.id, err)
	}
}

func mintToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// memSessions is proxy.Sessions in a map: process-local, for tests and single-process embedders.
// Same contract as the store, including atomic ReserveCrossing, so the Registry has one code path.
type memSessions struct {
	mu   sync.Mutex
	rows map[string]*memRow
}

type memRow struct {
	b    proxy.Binding
	used int
}

// NewMemorySessions returns an in-memory proxy.Sessions. Bindings do not survive the process and are
// not visible to other replicas; two Registries built over the SAME value do share them, which is how
// tests stand in two daemons.
func NewMemorySessions() proxy.Sessions { return &memSessions{rows: map[string]*memRow{}} }

func (m *memSessions) PutBinding(_ context.Context, b proxy.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.CreatedAt == "" {
		b.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	m.rows[b.ID] = &memRow{b: b}
	return nil
}

func (m *memSessions) GetBinding(_ context.Context, id string) (proxy.Binding, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return proxy.Binding{}, false, nil
	}
	return r.b, true, nil
}

func (m *memSessions) HasBinding(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.rows[id]
	return ok, nil
}

func (m *memSessions) DeleteBinding(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.rows[id]
	delete(m.rows, id)
	return ok, nil
}

func (m *memSessions) CountBindings(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows), nil
}

func (m *memSessions) ReserveCrossing(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return false, nil
	}
	if r.b.Budget > 0 && r.used >= r.b.Budget {
		return false, nil
	}
	r.used++
	return true, nil
}

func (m *memSessions) ReleaseCrossing(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok && r.used > 0 {
		r.used--
	}
	return nil
}

// Deps are the per-daemon gate ingredients shared across every session — everything EXCEPT the
// per-session Routes: the egress sink (the one owned audit log), the approval store + escalation
// hook (Stage 5), and the shared downstream to forward cleared calls to.
type Deps struct {
	Sink      proxy.Sink
	Approvals proxy.Approvals
	// Authorizations backs the one-shot grants that make a SEQUENCED route reachable for exactly
	// the call a recipe's `invoke` authorized. nil means sequenced routes stay unreachable.
	Authorizations proxy.Authorizations
	OnEscalate     func(ctx context.Context, n proxy.PendingNotice)
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
	reg.deps = deps // the registry compiles bindings (at bind, and when rehydrating) with these
	mux := http.NewServeMux()

	// DELETE /sessions/{token} REVOKES a binding. Same `dispatch` role as the binder: whoever may bind
	// a session to any recipe may also withdraw one, and it grants no authority the binder lacks.
	//
	// It is deliberately NOT reachable with the session's own token — an agent that could revoke (or
	// rebind) itself would be choosing its own policy, which is the thing the binder exists to prevent.
	mux.HandleFunc("DELETE /sessions/{token}", deps.Auth.Guard(auth.RoleDispatch)(func(w http.ResponseWriter, r *http.Request) {
		tok := r.PathValue("token")
		if tok == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "need a session token"})
			return
		}
		if !reg.Revoke(r.Context(), tok) {
			// Report the miss rather than a bare 200: "already gone" and "never existed" look the same
			// to an operator revoking in an incident, and that is exactly when they need to know.
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such session", "session": proxy.SessionID(tok)})
			return
		}
		log.Printf("session revoked: %s — the token no longer resolves; the agent holding it is served nothing", proxy.SessionID(tok))
		writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "session": proxy.SessionID(tok)})
	}))

	// POST /sessions is the TRUSTED binder — it chooses the recipe. `dispatch` role required.
	mux.HandleFunc("POST /sessions", deps.Auth.Guard(auth.RoleDispatch)(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Routes []struct {
				Tool      string `json:"tool"`
				Server    string `json:"server"` // WHICH MCP server serves it. The route delegates; the gate never infers.
				Recipe    string `json:"recipe"`
				GateArg   string `json:"gateArg"`
				Sequenced bool   `json:"sequenced"`
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
		routes := make([]proxy.BindingRoute, 0, len(req.Routes))
		for _, rt := range req.Routes {
			routes = append(routes, proxy.BindingRoute{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg, Sequenced: rt.Sequenced})
		}
		providers := make([]proxy.BindingProvider, 0, len(req.Context))
		for _, c := range req.Context {
			providers = append(providers, proxy.BindingProvider{Name: c.Name, Kind: c.Kind, Config: c.Config})
		}
		tok, rerrs, err := reg.Create(r.Context(), routes, providers)
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
		c, ok := reg.lookup(req.Context(), tok)
		if !ok {
			return nil // -> 400: no binding, no gate, nothing served
		}
		// The budget is the token's ONE shared counter, in the store — every MCP session the agent opens
		// under this token, on any replica, draws down the same N, so reconnecting cannot reset it.
		// Session is the token's audit id (a digest, never the token) so every decision this gate
		// records can be grouped back to the agent that made it — and to its row.
		// Live is re-evaluated on every request, so a revoke reaches THIS transport too — getServer runs
		// only once per MCP session, and a check made only here would never run again.
		gate := proxy.Gate{Routes: c.router, Sink: deps.Sink, Approvals: deps.Approvals, Authorizations: deps.Authorizations, OnEscalate: deps.OnEscalate,
			Budget:  reg.budget(tok, deps.CrossingBudget),
			Session: proxy.SessionID(tok), Live: func() bool { return reg.live(tok) }}
		read := mcpgate.ReadChannel{Providers: c.providers, Record: deps.RecordRead}
		return mcpgate.NewGatingServer(gate, deps.Fleet, read)
	}, &mcp.StreamableHTTPOptions{SessionTimeout: sessionIdleTimeout})

	// An unknown token must fail as a PROTOCOL error, not as a bare string. The SDK answers a nil
	// getServer with `http.Error(w, "no server available", 400)` — plain text an MCP client cannot
	// parse as JSON-RPC, so a revoked or mistyped token surfaces as an opaque transport failure and the
	// operator is left guessing. The token is still refused either way; this only makes the refusal
	// legible, and says the one thing that lets a client recover: rebind.
	mux.Handle("/mcp/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.URL.Path, "/mcp/")
		if _, ok := reg.lookup(r.Context(), tok); !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			// id:null — this refusal is not tied to any one request the client sent.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{
					"code":    -32001,
					"message": "unknown or revoked session token — rebind to continue",
				},
			})
			return
		}
		streamable.ServeHTTP(w, r)
	}))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions": reg.Count(r.Context())})
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
