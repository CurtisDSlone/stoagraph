package recipe_test

import (
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// A composed child's ARGUMENT BINDINGS are child-scoped names and must be namespaced like its
// slots and rules already are. Before this was fixed, splice prefixed the child's `propose`
// (out -> s0_node) but NOT the invoke's reference to it, so the child's own slot was orphaned
// and BOTH halves of the binding — the slot feeding the argument and the rule clearing it —
// silently resolved to the PARENT's same-named ones.
//
// The consequence was a privilege escalation: a child bounded to "staging-only" authorized a
// drain of "prod-db-master" once composed under a parent whose same-named rule was wider. The
// child's own rule became dead (warned as "unreferenced rule"), and the capture was invisible
// to anyone testing by varying the child's inputs, because binding s0_node had no effect at all.
//
// Every existing compose test used a SINK-ONLY child, which is precisely the case that always
// worked (ruleRef was namespaced). These tests cover the acting kinds.
// kw: composition namespace capture argrules privilege-escalation regression
const captureChild = `recipe: victim
version: 1
rules:
  node.target:
    kind: set_membership
    set: ["staging-only"]
steps:
  - {id: p, kind: propose, out: node}
  - {id: inv, kind: invoke, tool: k8s__drain_node,
     args: {node: {slot: node, rule: node.target}}, actor: "policy:victim"}
  - {id: e, kind: exit}
`

// The parent defines a rule with the SAME NAME and a WIDER set — the collision that triggered
// the capture. It also proposes its own `node`, the slot the child's invoke used to bind.
const captureParent = `recipe: attacker
version: 1
rules:
  node.target:
    kind: set_membership
    set: ["staging-only", "prod-db-master"]
  go.yes:
    kind: set_membership
    set: ["go"]
steps:
  - {id: p_mode, kind: propose, out: mode}
  - {id: p_node, kind: propose, out: node}
  - id: r
    kind: branch
    in: mode
    cases:
      - {rule: go.yes, goto_recipe: victim}
    default: skip
  - {id: skip, kind: exit}
`

func captureResolve(name string) ([]byte, error) {
	if name == "victim" {
		return []byte(captureChild), nil
	}
	return nil, errNoRecipe
}

var errNoRecipe = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "no such sub-recipe" }

// TestComposeDoesNotCaptureInvokeArgs is the core regression: the child must keep deciding its
// own call. A parent's same-named rule must not widen what the child authorizes.
func TestComposeDoesNotCaptureInvokeArgs(t *testing.T) {
	p, warns, err := recipe.Compose([]byte(captureParent), captureResolve)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}

	// 1. STRUCTURAL: both halves of the binding must point at the child's own names.
	var found bool
	for _, st := range p.Recipe.Steps {
		if st.Kind != stag.NodeInvoke {
			continue
		}
		found = true
		ar, ok := st.ArgRules["node"]
		if !ok {
			t.Fatalf("invoke %q has no ArgRule for \"node\"", st.Id)
		}
		if ar.Slot != "s0_node" {
			t.Errorf("invoke arg slot = %q, want \"s0_node\" (child's own slot; the parent's is \"node\")", ar.Slot)
		}
		if ar.RuleID != "s0_node.target" {
			t.Errorf("invoke arg rule = %q, want \"s0_node.target\" (child's own rule)", ar.RuleID)
		}
		// The tool name is NOT namespaced: <server>__<tool> names a real route, not a child scope.
		if st.Tool != "k8s__drain_node" {
			t.Errorf("tool = %q, want k8s__drain_node unchanged (a tool name is a real identifier)", st.Tool)
		}
	}
	if !found {
		t.Fatal("composed recipe has no invoke step")
	}

	// 2. BEHAVIOURAL: the value the child denies standalone must stay denied once composed,
	//    even though the parent's same-named rule admits it.
	res := stag.EvalArgs(p.Recipe, map[string]string{
		"mode": "go", "node": "prod-db-master",
	}, p.SemanticHash)
	if len(res.Authorized) != 0 {
		t.Errorf("CAPTURE: composed recipe authorized %d call(s) for a node the child forbids: %+v",
			len(res.Authorized), res.Authorized)
	}

	// 3. The child's OWN slot must actually drive the call now (it was dead before).
	res2 := stag.EvalArgs(p.Recipe, map[string]string{
		"mode": "go", "s0_node": "staging-only",
	}, p.SemanticHash)
	if len(res2.Authorized) != 1 {
		t.Errorf("child's own slot does not drive the call: authorized=%d, want 1", len(res2.Authorized))
	}

	// 4. The child's rule must no longer be dead.
	for _, w := range warns {
		if w == `unreferenced rule "s0_node.target"` {
			t.Errorf("child's rule is still unreferenced — the invoke is not using it: %q", w)
		}
	}
}

// TestComposeDoesNotCaptureReadQuery covers the same gap on a `read` step: querySlot and
// queryRule are child-scoped names too, and an uncaptured child must not gain the parent's
// wider query vocabulary.
func TestComposeDoesNotCaptureReadQuery(t *testing.T) {
	child := `recipe: victim
version: 1
providers: ["runbooks"]
rules:
  topic.narrow:
    kind: set_membership
    set: ["drain"]
steps:
  - {id: p, kind: propose, out: topic}
  - {id: rd, kind: read, provider: runbooks, query: {slot: topic, rule: topic.narrow}}
  - {id: e, kind: exit}
`
	parent := `recipe: attacker
version: 1
providers: ["runbooks"]
rules:
  topic.narrow:
    kind: set_membership
    set: ["drain", "control-plane"]
  go.yes:
    kind: set_membership
    set: ["go"]
steps:
  - {id: p_mode, kind: propose, out: mode}
  - {id: p_topic, kind: propose, out: topic}
  - id: r
    kind: branch
    in: mode
    cases:
      - {rule: go.yes, goto_recipe: victim}
    default: skip
  - {id: skip, kind: exit}
`
	p, _, err := recipe.Compose([]byte(parent), func(n string) ([]byte, error) {
		if n == "victim" {
			return []byte(child), nil
		}
		return nil, errNoRecipe
	})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	for _, st := range p.Recipe.Steps {
		if st.Kind != stag.NodeRead {
			continue
		}
		if st.QuerySlot != "s0_topic" {
			t.Errorf("read query slot = %q, want \"s0_topic\"", st.QuerySlot)
		}
		if st.QueryRuleID != "s0_topic.narrow" {
			t.Errorf("read query rule = %q, want \"s0_topic.narrow\"", st.QueryRuleID)
		}
		// The provider name is NOT namespaced — like a tool name, it is a real registration.
		if st.Provider != "runbooks" {
			t.Errorf("provider = %q, want runbooks unchanged", st.Provider)
		}
	}
	// The parent's wider topic must not authorize a read through the child's narrow rule.
	res := stag.EvalArgs(p.Recipe, map[string]string{"mode": "go", "topic": "control-plane"}, p.SemanticHash)
	if len(res.Reads) != 0 {
		t.Errorf("CAPTURE: composed read authorized for a topic the child forbids: %+v", res.Reads)
	}
}

// TestComposeNoCollisionStillFailsClosed pins the OTHER half of the behaviour: when the parent
// does NOT define the child's rule name, the composed reference must still resolve (to the
// child's own namespaced rule) rather than erroring. Before the fix this case was REFUSED
// outright with "unregistered rule", which is why no acting child could be composed at all.
func TestComposeNoCollisionStillComposes(t *testing.T) {
	parent := `recipe: attacker
version: 1
rules:
  go.yes:
    kind: set_membership
    set: ["go"]
steps:
  - {id: p_mode, kind: propose, out: mode}
  - id: r
    kind: branch
    in: mode
    cases:
      - {rule: go.yes, goto_recipe: victim}
    default: skip
  - {id: skip, kind: exit}
`
	p, _, err := recipe.Compose([]byte(parent), captureResolve)
	if err != nil {
		t.Fatalf("compose with no rule collision must succeed, got: %v", err)
	}
	res := stag.EvalArgs(p.Recipe, map[string]string{"mode": "go", "s0_node": "staging-only"}, p.SemanticHash)
	if len(res.Authorized) != 1 {
		t.Errorf("child's call not authorized under its own rule: %d", len(res.Authorized))
	}
	res2 := stag.EvalArgs(p.Recipe, map[string]string{"mode": "go", "s0_node": "prod-db-master"}, p.SemanticHash)
	if len(res2.Authorized) != 0 {
		t.Errorf("child's rule did not deny an out-of-set value: %+v", res2.Authorized)
	}
}
