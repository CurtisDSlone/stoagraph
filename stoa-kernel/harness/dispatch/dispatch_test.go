package dispatch_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
)

func TestGate(t *testing.T) {
	valid := []string{"k8s_incident_policy", "zt_refund_policy"}
	cases := []struct {
		id, conf string
		want     dispatch.GateDecision
	}{
		{"k8s_incident_policy", "high", dispatch.GateMatch},
		{"zt_refund_policy", "medium", dispatch.GateMatch},
		{"k8s_incident_policy", "low", dispatch.GateFallback}, // low confidence refused
		{"not_a_recipe", "high", dispatch.GateFallback},       // off-list refused (model can't invent)
		{"none", "high", dispatch.GateFallback},               // explicit none
		{"", "high", dispatch.GateFallback},                   // empty
	}
	for _, c := range cases {
		if got := dispatch.Gate(c.id, c.conf, valid); got != c.want {
			t.Errorf("Gate(%q,%q) = %v, want %v", c.id, c.conf, got, c.want)
		}
	}
}

func event(t *testing.T, js string) dispatch.Event {
	t.Helper()
	var e dispatch.Event
	if err := json.Unmarshal([]byte(js), &e); err != nil {
		t.Fatalf("bad event json: %v", err)
	}
	return e
}

func TestEventMapMatch(t *testing.T) {
	m := dispatch.EventMap{
		{ID: "pd-incident", Match: map[string]string{"source": "pagerduty", "event.type": "incident.triggered"}, Recipe: "k8s_incident_policy"},
		{ID: "stripe-refund", Match: map[string]string{"source": "stripe", "event.type": "charge.dispute.created"}, Recipe: "zt_refund_policy"},
		{ID: "bad", Match: map[string]string{}, Recipe: "never"}, // empty predicate must never match
	}
	// full match on nested dotted path
	if d, ok := m.Match(event(t, `{"source":"pagerduty","event":{"type":"incident.triggered"}}`)); !ok || d.ID != "pd-incident" {
		t.Errorf("pagerduty incident: got (%v,%v), want pd-incident", d.ID, ok)
	}
	// second definition
	if d, ok := m.Match(event(t, `{"source":"stripe","event":{"type":"charge.dispute.created"}}`)); !ok || d.ID != "stripe-refund" {
		t.Errorf("stripe refund: got (%v,%v)", d.ID, ok)
	}
	// partial match (one field wrong) -> no match
	if _, ok := m.Match(event(t, `{"source":"pagerduty","event":{"type":"incident.resolved"}}`)); ok {
		t.Error("a partial predicate match must NOT match")
	}
	// missing field -> no match; empty-predicate definition never rescues it
	if _, ok := m.Match(event(t, `{"source":"zendesk"}`)); ok {
		t.Error("unmatched event must not match (empty predicate is fail-closed)")
	}
}

type stubRouter struct{ res dispatch.RouteResult }

func (s stubRouter) Route(context.Context, dispatch.Event, []dispatch.Recipe) (dispatch.RouteResult, error) {
	return s.res, nil
}
func (s stubRouter) Name() string { return "stub" }

func TestDispatchDeterministicFirst(t *testing.T) {
	// a deterministic definition matches -> its recipe, NO model call (router would pick differently).
	d := dispatch.Dispatcher{
		Map:    dispatch.EventMap{{ID: "pd", Match: map[string]string{"source": "pagerduty"}, Recipe: "k8s_incident_policy"}},
		Router: stubRouter{dispatch.RouteResult{RecipeID: "WRONG", Confidence: "high"}},
		Catalog: func() ([]dispatch.Recipe, error) {
			return []dispatch.Recipe{{ID: "k8s_incident_policy"}, {ID: "WRONG"}}, nil
		},
	}
	dec, err := d.Dispatch(context.Background(), event(t, `{"source":"pagerduty"}`))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mode != "deterministic" || dec.RecipeID != "k8s_incident_policy" || dec.Definition != "pd" {
		t.Fatalf("deterministic-first: got %+v", dec)
	}
}

func TestDispatchModelFallbackAndGate(t *testing.T) {
	cat := func() ([]dispatch.Recipe, error) { return []dispatch.Recipe{{ID: "zt_refund_policy"}}, nil }
	base := dispatch.Dispatcher{Map: nil, Catalog: cat} // no deterministic match -> model route

	// model names a valid recipe at good confidence -> dispatch
	base.Router = stubRouter{dispatch.RouteResult{RecipeID: "zt_refund_policy", Confidence: "high"}}
	if dec, _ := base.Dispatch(context.Background(), event(t, `{"source":"stripe"}`)); dec.Mode != "model" || dec.RecipeID != "zt_refund_policy" {
		t.Fatalf("model route: got %+v", dec)
	}

	// low confidence -> Gate rejects -> none
	base.Router = stubRouter{dispatch.RouteResult{RecipeID: "zt_refund_policy", Confidence: "low"}}
	if dec, _ := base.Dispatch(context.Background(), event(t, `{}`)); dec.Dispatched() {
		t.Fatalf("low confidence must not dispatch: %+v", dec)
	}

	// off-list recipe (model tried to invent) -> Gate rejects -> none
	base.Router = stubRouter{dispatch.RouteResult{RecipeID: "made_up", Confidence: "high"}}
	if dec, _ := base.Dispatch(context.Background(), event(t, `{}`)); dec.Dispatched() {
		t.Fatalf("off-list recipe must not dispatch: %+v", dec)
	}

	// no router at all -> none (deterministic-only deployment)
	base.Router = nil
	if dec, _ := base.Dispatch(context.Background(), event(t, `{}`)); dec.Mode != "none" {
		t.Fatalf("no router: want none, got %+v", dec)
	}
}

func TestParseRouteLenient(t *testing.T) {
	// tolerate a code fence + prose around the JSON
	rr := dispatch.ParseRoute("Sure!\n```json\n{\"recipe_id\": \"zt_refund_policy\", \"confidence\": \"High\"}\n```\n")
	if rr.RecipeID != "zt_refund_policy" || rr.Confidence != "high" {
		t.Errorf("lenient parse: got %+v", rr)
	}
	// garbage -> fail-closed defaults
	if rr := dispatch.ParseRoute("no json here"); rr.RecipeID != "none" || rr.Confidence != "low" {
		t.Errorf("garbage parse: got %+v", rr)
	}
}
