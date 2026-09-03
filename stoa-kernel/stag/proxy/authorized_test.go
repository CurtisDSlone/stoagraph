package proxy

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// A Decision must carry the calls its recipe AUTHORIZED, so a caller can hand them to the
// executor. The rules are the kernel's, surfaced honestly at the boundary: a call is only
// authorized if the whole decision forwarded, and a fanned-out evaluation must not multiply
// the sequence.

func invokeRecipeFor(t *testing.T, tool string) (stag.Recipe, string) {
	t.Helper()
	rule := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"dev", "staging"}}
	return stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "ns"},
		{Id: "one", Kind: stag.NodeInvoke, Tool: tool, ArgRules: map[string]stag.ArgRule{"node": {Slot: "ns", Rule: &rule, RuleID: "ns.safe"}}, Actor: "policy:test"},
	}}, "h-invoke"
}

func TestDecisionCarriesAuthorizedCalls(t *testing.T) {
	r, h := invokeRecipeFor(t, "k8s.drain")
	g := Gate{Routes: Router{"plan": {Recipe: r, RecipeHash: h, RecipeName: "p", GateArg: "ns"}}}
	d := g.Decide(context.Background(), ToolCall{Tool: "plan", Args: map[string]string{"ns": "dev"}})
	if !d.Forward {
		t.Fatalf("allowed call must forward: %+v", d)
	}
	if len(d.Authorized) != 1 || d.Authorized[0].Tool != "k8s.drain" {
		t.Fatalf("decision must carry the authorized calls: %+v", d.Authorized)
	}
	if d.Authorized[0].Args["node"] != "dev" {
		t.Errorf("authorized args must be the cleared values: %+v", d.Authorized[0].Args)
	}
}

// A decision that does not forward authorizes nothing — the same retraction the kernel makes,
// enforced again at the boundary so a caller can never read a plan off a refused decision.
func TestNonForwardedDecisionAuthorizesNothing(t *testing.T) {
	r, h := invokeRecipeFor(t, "k8s.drain")
	g := Gate{Routes: Router{"plan": {Recipe: r, RecipeHash: h, RecipeName: "p", GateArg: "ns"}}}
	d := g.Decide(context.Background(), ToolCall{Tool: "plan", Args: map[string]string{"ns": "prod"}})
	if d.Forward {
		t.Fatal("prod must not forward")
	}
	if len(d.Authorized) != 0 {
		t.Errorf("a refused decision must authorize nothing: %+v", d.Authorized)
	}
}

// An unrouted tool authorizes nothing (and is still recorded).
func TestUnroutedAuthorizesNothing(t *testing.T) {
	g := Gate{Routes: Router{}}
	d := g.Decide(context.Background(), ToolCall{Tool: "nope", Args: map[string]string{"a": "b"}})
	if len(d.Authorized) != 0 || d.Forward {
		t.Errorf("unrouted: %+v", d)
	}
}

// A multi-value path fans the evaluation into several combinations. The authorized sequence
// is the RECIPE's, not the fan-out's: N combinations must not authorize N copies of the call.
// Getting this wrong would let one proposal multiply the actions a policy authorizes.
func TestFanOutDoesNotMultiplyAuthorizations(t *testing.T) {
	rule := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"dev", "staging"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "ns"},
		{Id: "one", Kind: stag.NodeInvoke, Tool: "k8s.drain", ArgRules: map[string]stag.ArgRule{"node": {Slot: "ns", Rule: &rule, RuleID: "ns.safe"}}, Actor: "policy:test"},
	}}
	g := Gate{Routes: Router{"plan": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "items[].ns"}}}
	call := ToolCall{Tool: "plan", Raw: []byte(`{"items":[{"ns":"dev"},{"ns":"staging"}]}`)}
	d := g.Decide(context.Background(), call)
	if !d.Forward {
		t.Fatalf("both values clear, so the call forwards: %+v", d)
	}
	if len(d.Authorized) > 1 {
		t.Errorf("fan-out must not multiply the authorized sequence: %d calls %+v", len(d.Authorized), d.Authorized)
	}
}

// If ANY combination in a fan-out is refused, the whole decision is refused and nothing is
// authorized — one bad element cannot leave a partially-authorized sequence behind.
func TestFanOutOneRefusedAuthorizesNothing(t *testing.T) {
	rule := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"dev", "staging"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "ns"},
		{Id: "one", Kind: stag.NodeInvoke, Tool: "k8s.drain", ArgRules: map[string]stag.ArgRule{"node": {Slot: "ns", Rule: &rule, RuleID: "ns.safe"}}, Actor: "policy:test"},
	}}
	g := Gate{Routes: Router{"plan": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "items[].ns"}}}
	call := ToolCall{Tool: "plan", Raw: []byte(`{"items":[{"ns":"dev"},{"ns":"prod"}]}`)}
	d := g.Decide(context.Background(), call)
	if d.Forward {
		t.Fatal("one refused element must refuse the decision")
	}
	if len(d.Authorized) != 0 {
		t.Errorf("must authorize nothing: %+v", d.Authorized)
	}
}

// A recipe with no invoke steps authorizes nothing: every existing route is unaffected.
func TestOrdinaryRecipeAuthorizesNothing(t *testing.T) {
	rule := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"dev"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "ns"},
		{Id: "s", Kind: stag.NodeSink, In: "ns", Field: "k8s.f", Sensitivity: stag.SinkAuthoritative,
			Rule: &rule, RuleID: "r", Actor: "a"},
	}}
	g := Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "ns"}}}
	d := g.Decide(context.Background(), ToolCall{Tool: "t", Args: map[string]string{"ns": "dev"}})
	if !d.Forward || len(d.Authorized) != 0 {
		t.Errorf("ordinary recipe: %+v", d)
	}
}
