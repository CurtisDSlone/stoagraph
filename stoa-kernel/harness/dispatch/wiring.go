package dispatch

// file-kw: wiring stag-serve catalog routes-for-recipe session binder daemon post-sessions token

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RouteSpec is one tool→server→recipe→gateArg binding — what a session is built from.
//
// SERVER IS REQUIRED. The daemon rejects a binding whose route names no server ("route names no MCP
// server"), because the gate never infers which downstream a tool belongs to. Dropping it here meant
// every dispatcher-bound session was refused with "no valid routes in binding" — the orchestrator's
// whole agent path. It is carried end to end: /api/routes -> RouteSpec -> POST /sessions.
type RouteSpec struct {
	Tool    string `json:"tool"`
	Server  string `json:"server"`
	Recipe  string `json:"recipe"`
	GateArg string `json:"gateArg"`
	// Sequenced: bound only for a recipe's `invoke` to authorize — not advertised to the agent,
	// and unreachable without a one-shot grant. MUST be carried through from routeRow: dropping it
	// here means every session-bound route looks unsequenced to stag-proxy regardless of what
	// config.db says, silently disabling grant-only enforcement for every dispatched session.
	Sequenced bool `json:"sequenced"`
}

// ProviderSpec is one resolved context provider — the READ-channel half of a session binding
// (Planning/30). The daemon builds a live provider from {name, kind, config}; the agent never sees it.
type ProviderSpec struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Config string `json:"config"`
}

// StagClient reads the routable policy from stag-serve (the console's API): the recipe catalog for
// the dispatch model, and the routes that a chosen recipe governs (to build a session).
//
// Token is the control-plane `dispatch` secret (Planning/31) — the ORCHESTRATOR's role. It admits
// catalog reads and the approval POLL. It deliberately CANNOT approve or write policy: an
// orchestrator able to approve its own escalations would make the human gate decorative.
type StagClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c StagClient) httpc() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Catalog lists the ACTIONABLE recipes for the dispatch model — the distinct recipes that have a
// valid route (i.e. can actually govern a session). A recipe with no route can't be bound, so
// offering it would only let the model pick an unbindable target; the catalog excludes them. Recipes
// carry no description today, so WhenToUse is the name (the deterministic event map, which names
// recipes explicitly, is the primary path). Suitable as a Dispatcher.Catalog.
func (c StagClient) Catalog() ([]Recipe, error) {
	var routes []struct {
		Recipe string `json:"recipe"`
		Valid  bool   `json:"valid"`
	}
	if err := c.get("/api/routes", &routes); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]Recipe, 0)
	for _, r := range routes {
		if r.Valid && !seen[r.Recipe] {
			seen[r.Recipe] = true
			out = append(out, Recipe{ID: r.Recipe, WhenToUse: r.Recipe})
		}
	}
	return out, nil
}

// RoutesForRecipe returns the route bindings a recipe governs (the session's routes). A recipe with
// no route is not actionable — the session would have nothing to gate (fail closed at bind).
func (c StagClient) RoutesForRecipe(recipe string) ([]RouteSpec, error) {
	routes, err := c.routes()
	if err != nil {
		return nil, err
	}
	out := make([]RouteSpec, 0, 1)
	for _, r := range routes {
		if r.Recipe == recipe && r.Valid {
			out = append(out, RouteSpec{Tool: r.Tool, Server: r.Server, Recipe: r.Recipe, GateArg: r.GateArg, Sequenced: r.Sequenced})
		}
	}
	return out, nil
}

// advertisedName mirrors stag/proxy/naming.go's AdvertisedName (server + "__" + tool) without
// importing stag/proxy: this package talks to stag-serve over HTTP only, the same one-way
// boundary RouteSpec/routeRow already keep by duplicating the wire shape rather than importing
// the gate's own types.
func advertisedName(server, tool string) string { return server + "__" + tool }

// RoutesForTools returns the route bindings for a given set of ADVERTISED tool names
// (<server>__<tool>), regardless of which recipe those routes are themselves bound to.
//
// This is how a session reaches a SEQUENCE's sub-tools. A recipe's invoke/await steps authorize
// calls on OTHER recipes' tools — a sequenced sub-tool is deliberately routed to its own separate
// recipe, never the recipe that invokes it (see the invoke/await wiring invariants), so
// RoutesForRecipe(the trigger recipe's name) alone never returns those sub-tool routes. Callers
// resolve `names` from ValidateResult.InvokedTools (the trigger recipe's own steps — the only
// source of truth for which sub-tools a sequence needs) and union the result with
// RoutesForRecipe's, deduped by advertised name.
func (c StagClient) RoutesForTools(names []string) ([]RouteSpec, error) {
	if len(names) == 0 {
		return nil, nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	routes, err := c.routes()
	if err != nil {
		return nil, err
	}
	out := make([]RouteSpec, 0, len(names))
	for _, r := range routes {
		if r.Valid && want[advertisedName(r.Server, r.Tool)] {
			out = append(out, RouteSpec{Tool: r.Tool, Server: r.Server, Recipe: r.Recipe, GateArg: r.GateArg, Sequenced: r.Sequenced})
		}
	}
	return out, nil
}

// RoutesForSession resolves the FULL route set a session governed by `recipeName` needs: that
// recipe's own routes (RoutesForRecipe), unioned with the routes for every sub-tool its own
// invoke/await steps authorize (RoutesForTools, resolved via InvokedToolsForRecipe). Deduped by
// advertised name — a tool the trigger recipe both routes directly AND invokes as a sub-call
// (unusual, but not forbidden) appears once.
//
// This is the fix for the invoke-only-recipe gap: a trigger recipe that is ENTIRELY invoke/await
// steps has no route of its own that matters beyond its trigger tool, and its sub-tools are
// (correctly) routed to separate recipes RoutesForRecipe alone would never reach.
func (c StagClient) RoutesForSession(recipeName string) ([]RouteSpec, error) {
	direct, err := c.RoutesForRecipe(recipeName)
	if err != nil {
		return nil, err
	}
	tools, err := c.InvokedToolsForRecipe(recipeName)
	if err != nil {
		return nil, err
	}
	sub, err := c.RoutesForTools(tools)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(direct)+len(sub))
	out := make([]RouteSpec, 0, len(direct)+len(sub))
	for _, rs := range direct {
		adv := advertisedName(rs.Server, rs.Tool)
		if !seen[adv] {
			seen[adv] = true
			out = append(out, rs)
		}
	}
	for _, rs := range sub {
		adv := advertisedName(rs.Server, rs.Tool)
		if !seen[adv] {
			seen[adv] = true
			out = append(out, rs)
		}
	}
	return out, nil
}

// ProviderNamesForSession resolves the FULL set of context-provider NAMES a session governed by
// `recipeName` may read: that recipe's own providers: allowlist, unioned with the providers:
// allowlist of every DISTINCT sub-recipe its sequence's sub-tools are routed to (resolved from
// RoutesForSession's own route set — a route's Recipe field names the recipe governing it).
//
// Without this, a trigger recipe that is entirely invoke/await (declaring no providers: of its
// own, since it makes no read calls itself) binds a session with NO read channel at all, even
// when the sequence it authorizes is clearly meant to act on a briefing one of its sub-recipes
// declares — the agent then has nothing but the raw trigger event to reason from.
func (c StagClient) ProviderNamesForSession(recipeName string, routes []RouteSpec) ([]string, error) {
	names, err := c.ProviderNamesForRecipe(recipeName)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	subRecipes := map[string]bool{recipeName: true} // the trigger's own is already counted
	for _, rs := range routes {
		if subRecipes[rs.Recipe] {
			continue
		}
		subRecipes[rs.Recipe] = true
		sn, serr := c.ProviderNamesForRecipe(rs.Recipe)
		if serr != nil {
			continue // fail open on a SINGLE sub-recipe's providers, not the whole session — a sub-recipe that fails to resolve just contributes no context of its own
		}
		for _, n := range sn {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// ProviderNamesForRecipe returns the context-provider names a recipe itself declares (its
// Recipe.Providers allowlist) — the READ-channel counterpart to RoutesForRecipe. Which providers a
// session may read comes entirely from the RECIPE now, not the event map: fetch its own
// declaration, then resolve those names to specs via ProvidersFor. An empty/absent recipe (no
// providers: block) yields no names — no READ channel, same as today's "empty Context" case.
func (c StagClient) ProviderNamesForRecipe(recipeName string) ([]string, error) {
	var detail struct {
		Result struct {
			Providers []string `json:"providers"`
		} `json:"result"`
	}
	if err := c.get("/api/recipes/"+recipeName, &detail); err != nil {
		return nil, err
	}
	return detail.Result.Providers, nil
}

// InvokedToolsForRecipe returns the advertised tool names (<server>__<tool>) a recipe's own
// invoke/await steps authorize (ValidateResult.InvokedTools) — the sub-tools a sequence needs
// routes bound for. See RoutesForTools.
func (c StagClient) InvokedToolsForRecipe(recipeName string) ([]string, error) {
	var detail struct {
		Result struct {
			InvokedTools []string `json:"invokedTools"`
		} `json:"result"`
	}
	if err := c.get("/api/recipes/"+recipeName, &detail); err != nil {
		return nil, err
	}
	return detail.Result.InvokedTools, nil
}

// routeRow is one row of GET /api/routes. `server` is part of the binding and must be carried through
// to the session — the daemon refuses a route that does not name one.
type routeRow struct {
	Tool      string `json:"tool"`
	Server    string `json:"server"`
	Recipe    string `json:"recipe"`
	GateArg   string `json:"gateArg"`
	Sequenced bool   `json:"sequenced"`
	Valid     bool   `json:"valid"`
}

func (c StagClient) routes() ([]routeRow, error) {
	var routes []routeRow
	if err := c.get("/api/routes", &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// ProvidersFor resolves a set of context-provider NAMES to their specs (the READ-channel binding,
// Planning/30), keeping only ENABLED providers. An unknown or disabled name is silently dropped —
// fail closed: the session simply gets no READ channel for it, never a fabricated source. Empty names
// -> no providers (no READ channel).
func (c StagClient) ProvidersFor(names []string) ([]ProviderSpec, error) {
	if len(names) == 0 {
		return nil, nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var provs []struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Config  string `json:"config"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.get("/api/providers", &provs); err != nil {
		return nil, err
	}
	out := make([]ProviderSpec, 0, len(names))
	for _, p := range provs {
		if want[p.Name] && p.Enabled {
			out = append(out, ProviderSpec{Name: p.Name, Kind: p.Kind, Config: p.Config})
		}
	}
	return out, nil
}

func (c StagClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token) // the `dispatch` role
	}
	resp, err := c.httpc().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("stag %s: 401 — the orchestrator's `dispatch` control-plane token is missing or wrong", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stag %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Binder binds a session on the stag-proxy DAEMON: POST /sessions {routes} → an opaque token whose
// /mcp/<token> endpoint gates against exactly those routes.
type Binder struct {
	DaemonURL string
	Token     string // the control-plane `dispatch` secret — POST /sessions requires it (Planning/31)
	HTTP      *http.Client
}

// Bind registers a session for the given routes (ACT) and context providers (READ) and returns the
// /mcp/<token> endpoint the agent connects to. Fails if no routes (nothing to gate) or the daemon
// rejects the binding (bad recipe). Providers may be empty — a session with no READ channel.
func (b Binder) Bind(ctx context.Context, routes []RouteSpec, providers []ProviderSpec) (endpoint, token string, err error) {
	if len(routes) == 0 {
		return "", "", fmt.Errorf("no routes to bind (recipe is not routed to any tool)")
	}
	body, _ := json.Marshal(map[string]any{"routes": routes, "context": providers})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.DaemonURL+"/sessions", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token) // the `dispatch` role
	}
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("bind session: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return "", "", fmt.Errorf("bind session: 401 — the orchestrator's `dispatch` control-plane token is missing or wrong")
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("bind session: HTTP %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", "", fmt.Errorf("bind session: bad response: %s", raw)
	}
	return b.DaemonURL + out.Path, out.Token, nil
}
