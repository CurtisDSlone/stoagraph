package dispatch_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
)

func TestStagClientCatalogAndRoutes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routes", func(w http.ResponseWriter, _ *http.Request) {
		// scale is routed; a same-recipe second route (get_events) must dedupe; an INVALID route
		// (broken recipe) must be excluded; an unrouted recipe (zt_refund_policy) never appears.
		// EVERY row carries its `server` — the daemon refuses a binding that does not name one.
		_, _ = w.Write([]byte(`[
			{"tool":"scale_deployment","server":"k8s","recipe":"k8s_scale_approval_policy","gateArg":"namespace,replicas,approval_token","valid":true},
			{"tool":"get_pods","server":"k8s","recipe":"k8s_read_policy","gateArg":"namespace","valid":true},
			{"tool":"get_events","server":"k8s","recipe":"k8s_read_policy","gateArg":"namespace","valid":true},
			{"tool":"x","server":"k8s","recipe":"broken","gateArg":"y","valid":false}
		]`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := dispatch.StagClient{BaseURL: ts.URL}

	// catalog = distinct ACTIONABLE recipes (routed + valid); deduped; broken/unrouted excluded
	cat, err := c.Catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	ids := dispatch.RecipeIDs(cat)
	if !dispatch.Contains(ids, "k8s_scale_approval_policy") || !dispatch.Contains(ids, "k8s_read_policy") {
		t.Fatalf("catalog: got %v, want the routed recipes", ids)
	}
	if dispatch.Contains(ids, "broken") || dispatch.Contains(ids, "zt_refund_policy") {
		t.Fatalf("catalog: got %v, must exclude invalid/unrouted recipes", ids)
	}
	if len(ids) != 2 {
		t.Fatalf("catalog must dedupe same-recipe routes: got %v", ids)
	}

	// a recipe's routes are the tool bindings it governs (the session spec)
	routes, err := c.RoutesForRecipe("k8s_scale_approval_policy")
	if err != nil {
		t.Fatalf("routes: %v", err)
	}
	if len(routes) != 1 || routes[0].Tool != "scale_deployment" || routes[0].GateArg != "namespace,replicas,approval_token" {
		t.Fatalf("routes for recipe: got %+v", routes)
	}
	// REGRESSION: the SERVER must survive the trip. Dropping it here made every dispatcher-bound
	// session fail at the daemon with "no valid routes in binding" — the orchestrator's whole agent
	// path — and no test caught it because the fixture did not carry a server either.
	if routes[0].Server != "k8s" {
		t.Fatalf("route must carry its server to the session binding: got %+v", routes[0])
	}

	// an unrouted recipe yields no routes (not actionable — Bind will refuse it)
	if r, _ := c.RoutesForRecipe("zt_refund_policy"); len(r) != 0 {
		t.Errorf("unrouted recipe should have no routes, got %+v", r)
	}
}

// TestProvidersFor asserts the READ-channel resolution (Planning/30): only REQUESTED and ENABLED
// providers are returned; unknown or disabled names are dropped (fail closed, no fabrication).
func TestProvidersFor(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/providers", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"name":"k8s-kb","kind":"http","config":"{\"url\":\"http://localhost:8095/context\"}","enabled":true},
			{"name":"disabled-kb","kind":"http","config":"{}","enabled":false},
			{"name":"other","kind":"http","config":"{}","enabled":true}
		]`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := dispatch.StagClient{BaseURL: ts.URL}

	// empty names -> no READ channel, no HTTP call needed
	if got, err := c.ProvidersFor(nil); err != nil || got != nil {
		t.Fatalf("empty names must yield nil providers: got %v, err %v", got, err)
	}

	// request k8s-kb (enabled) + disabled-kb (disabled) + ghost (unknown)
	got, err := c.ProvidersFor([]string{"k8s-kb", "disabled-kb", "ghost"})
	if err != nil {
		t.Fatalf("ProvidersFor: %v", err)
	}
	if len(got) != 1 || got[0].Name != "k8s-kb" || got[0].Kind != "http" {
		t.Fatalf("must keep only requested+enabled: got %+v", got)
	}
	if got[0].Config == "" {
		t.Errorf("config must be passed through for the daemon to build the provider: %+v", got[0])
	}
}

// TestRoutesForSessionReachesSequenceSubTools is the regression test for the invoke-only-recipe
// gap: a TRIGGER recipe (cordon_seq) is bound to its own route (the trigger tool), but its
// invoke/await steps authorize calls on cordon_node/drain_node — tools routed to a SEPARATE
// recipe (maint_policy), as the invoke/await wiring invariants require. RoutesForRecipe alone
// would return only the trigger route; RoutesForSession must also reach the sub-tool routes.
func TestRoutesForSessionReachesSequenceSubTools(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routes", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"tool":"start_maintenance","server":"ops","recipe":"cordon_seq","gateArg":"node","valid":true},
			{"tool":"cordon_node","server":"k8s","recipe":"maint_policy","gateArg":"node","sequenced":true,"valid":true},
			{"tool":"drain_node","server":"k8s","recipe":"maint_policy","gateArg":"node","sequenced":true,"valid":true},
			{"tool":"unrelated","server":"k8s","recipe":"other_policy","gateArg":"x","valid":true}
		]`))
	})
	mux.HandleFunc("/api/recipes/cordon_seq", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"invokedTools":["k8s__cordon_node","k8s__drain_node"]}}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := dispatch.StagClient{BaseURL: ts.URL}

	routes, err := c.RoutesForSession("cordon_seq")
	if err != nil {
		t.Fatalf("RoutesForSession: %v", err)
	}
	byTool := map[string]dispatch.RouteSpec{}
	for _, r := range routes {
		byTool[r.Tool] = r
	}
	if len(routes) != 3 {
		t.Fatalf("expected trigger route + 2 sub-tool routes, got %d: %+v", len(routes), routes)
	}
	if _, ok := byTool["start_maintenance"]; !ok {
		t.Errorf("must include the trigger recipe's own route: %+v", routes)
	}
	if r, ok := byTool["cordon_node"]; !ok || r.Recipe != "maint_policy" || !r.Sequenced {
		t.Errorf("must include the sequenced sub-tool route, bound to ITS OWN recipe: %+v", byTool["cordon_node"])
	}
	if r, ok := byTool["drain_node"]; !ok || r.Recipe != "maint_policy" || !r.Sequenced {
		t.Errorf("must include the second sequenced sub-tool route: %+v", byTool["drain_node"])
	}
	if _, ok := byTool["unrelated"]; ok {
		t.Errorf("must NOT include a route this recipe never invokes: %+v", routes)
	}
}

// TestProviderNamesForSessionUnionsSubRecipes is the READ-channel half of the same regression: an
// invoke-only trigger recipe declares no providers: of its own, but the sub-recipe its sequence
// invokes does — without the union, a session for this trigger gets NO read channel at all, even
// though the sequence clearly needs the briefing its sub-recipe names.
func TestProviderNamesForSessionUnionsSubRecipes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/recipes/cordon_seq", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"providers":[]}}`))
	})
	mux.HandleFunc("/api/recipes/maint_policy", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"providers":["runbooks"]}}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := dispatch.StagClient{BaseURL: ts.URL}

	routes := []dispatch.RouteSpec{
		{Tool: "start_maintenance", Server: "ops", Recipe: "cordon_seq"},
		{Tool: "cordon_node", Server: "k8s", Recipe: "maint_policy", Sequenced: true},
		{Tool: "drain_node", Server: "k8s", Recipe: "maint_policy", Sequenced: true}, // same sub-recipe twice: must not double-fetch/duplicate
	}
	names, err := c.ProviderNamesForSession("cordon_seq", routes)
	if err != nil {
		t.Fatalf("ProviderNamesForSession: %v", err)
	}
	if len(names) != 1 || names[0] != "runbooks" {
		t.Fatalf("expected the sub-recipe's own providers unioned in, got %v", names)
	}
}
