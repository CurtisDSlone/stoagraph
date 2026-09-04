package proxy

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

func readGate(t *testing.T) Gate {
	t.Helper()
	topic := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"drain"}}
	node := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"kind-worker"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p_t", Kind: stag.NodePropose, Out: "topic"},
		{Id: "p_n", Kind: stag.NodePropose, Out: "node"},
		{Id: "brief", Kind: stag.NodeRead, Provider: "runbooks",
			QuerySlot: "topic", QueryRule: &topic, QueryRuleID: "topic.allowed"},
		{Id: "act", Kind: stag.NodeSink, In: "node", Field: "k8s.act",
			Sensitivity: stag.SinkAuthoritative, Rule: &node, RuleID: "node.worker", Actor: "a"},
	}}
	return Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "topic,node"}}}
}

// An allowed decision carries the reads the recipe authorized.
func TestDecisionCarriesAuthorizedReads(t *testing.T) {
	g := readGate(t)
	d := g.Decide(context.Background(), ToolCall{Tool: "t",
		Args: map[string]string{"topic": "drain", "node": "kind-worker"}})
	if !d.Forward {
		t.Fatalf("must forward: %+v", d)
	}
	if len(d.Reads) != 1 || d.Reads[0].Provider != "runbooks" || d.Reads[0].Query != "drain" {
		t.Errorf("decision must carry the authorized reads: %+v", d.Reads)
	}
}

// A REFUSED decision still carries them. This is the deliberate difference from Authorized:
// a read cannot cause a denial, and the context explaining a refusal is most needed exactly
// when the action was refused.
func TestRefusedDecisionStillCarriesReads(t *testing.T) {
	g := readGate(t)
	d := g.Decide(context.Background(), ToolCall{Tool: "t",
		Args: map[string]string{"topic": "drain", "node": "kind-control-plane"}})
	if d.Forward {
		t.Fatal("the action must be refused")
	}
	if len(d.Reads) != 1 {
		t.Error("a refused decision must still carry its reads — they explain the refusal")
	}
	if len(d.Authorized) != 0 {
		t.Error("but no CALL is authorized")
	}
}

// A query outside its rule authorizes no read, and still does not deny the action.
func TestUngatedQueryYieldsNoReadButAllowsTheAction(t *testing.T) {
	g := readGate(t)
	d := g.Decide(context.Background(), ToolCall{Tool: "t",
		Args: map[string]string{"topic": "secrets", "node": "kind-worker"}})
	if !d.Forward {
		t.Errorf("a refused read query must not deny the action: %+v", d)
	}
	if len(d.Reads) != 0 {
		t.Error("and the ungated query must authorize no read")
	}
}
