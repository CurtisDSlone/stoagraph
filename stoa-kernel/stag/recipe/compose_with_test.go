package recipe_test

import (
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// `with:` on a goto_recipe case maps a CHILD entry slot to a PARENT slot that feeds it.
//
// It exists because composition namespaces a child's slots by splice position (node -> s0_node)
// and a route's gateArg can only name slots an author actually wrote — so without a mapping a
// composed child's slots are unbindable and its arc is unreachable.
//
// The load-bearing property: `with` moves the VALUE, never the DECISION. The child's invoke ends
// up reading the parent's SLOT under the CHILD's own RULE. A parent cannot widen what its child
// authorizes by feeding it — that was the argument-capture defect, and this must not reintroduce it.
// kw: composition with entry-slot reachability parent-feeds-child rule-stays-child
const withChild = `recipe: wchild
version: 1
rules:
  node.narrow:
    kind: set_membership
    set: ["kind-worker2"]
steps:
  - {id: p, kind: propose, out: node}
  - {id: act, kind: invoke, tool: k8s__drain_node,
     args: {node: {slot: node, rule: node.narrow}}, actor: "policy:wchild"}
  - {id: e, kind: exit}
`

// The parent's own rule is deliberately WIDER than the child's.
const withParent = `recipe: wparent
version: 1
rules:
  mode.drain:
    kind: set_membership
    set: ["drain"]
  node.wide:
    kind: set_membership
    set: ["kind-worker", "kind-worker2", "kind-control-plane"]
steps:
  - {id: p_mode, kind: propose, out: mode}
  - {id: p_node, kind: propose, out: node}
  - {id: s_node, kind: sink, in: node, field: k8s.w.node,
     sensitivity: authoritative, rule: node.wide, actor: "policy:wparent"}
  - id: br
    kind: branch
    in: mode
    cases:
      - {rule: mode.drain, goto_recipe: wchild, with: {node: node}}
    default: fin
  - {id: fin, kind: exit}
`

func withResolve(name string) ([]byte, error) {
	if name == "wchild" {
		return []byte(withChild), nil
	}
	return nil, errNoRecipe
}

func TestComposeWithMapsEntrySlot(t *testing.T) {
	p, warns, err := recipe.Compose([]byte(withParent), withResolve)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	for _, w := range warns {
		if w == `unreferenced rule "s0_node.narrow"` {
			t.Errorf("child's rule went dead — `with` must not detach it: %q", w)
		}
	}

	// STRUCTURAL: the parent's slot feeds it, the CHILD's rule still decides it.
	var seen bool
	for _, st := range p.Recipe.Steps {
		if st.Kind != stag.NodeInvoke {
			continue
		}
		seen = true
		ar := st.ArgRules["node"]
		if ar.Slot != "node" {
			t.Errorf("arg slot = %q, want %q (the PARENT slot a gateArg can bind)", ar.Slot, "node")
		}
		if ar.RuleID != "s0_node.narrow" {
			t.Errorf("arg rule = %q, want %q (the CHILD's own rule)", ar.RuleID, "s0_node.narrow")
		}
	}
	if !seen {
		t.Fatal("no invoke step in the composed recipe")
	}

	// BEHAVIOURAL: the child's narrower rule governs, even though the parent's admits more.
	in := stag.EvalArgs(p.Recipe, map[string]string{"mode": "drain", "node": "kind-worker2"}, p.SemanticHash)
	if len(in.Authorized) != 1 {
		t.Errorf("in-scope node not authorized: %d calls", len(in.Authorized))
	}
	for _, bad := range []string{"kind-worker", "kind-control-plane"} {
		r := stag.EvalArgs(p.Recipe, map[string]string{"mode": "drain", "node": bad}, p.SemanticHash)
		if len(r.Authorized) != 0 {
			t.Errorf("WIDENED: parent fed %q past the child's own rule: %+v", bad, r.Authorized)
		}
	}
}

// Every malformed mapping must fail closed at author time.
func TestComposeWithFailsClosed(t *testing.T) {
	mk := func(with string) []byte {
		return []byte(`recipe: wparent2
version: 1
rules:
  mode.drain:
    kind: set_membership
    set: ["drain"]
steps:
  - {id: p_mode, kind: propose, out: mode}
  - {id: p_node, kind: propose, out: node}
  - id: br
    kind: branch
    in: mode
    cases:
      - {rule: mode.drain, goto_recipe: wchild` + with + `}
    default: fin
  - {id: fin, kind: exit}
`)
	}
	for _, tc := range []struct{ name, with string }{
		{"slot the child does not propose", ", with: {nosuch: node}"},
		{"nonexistent parent slot", ", with: {node: ghost}"},
		{"empty mapping", ", with: {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := recipe.Compose(mk(tc.with), withResolve); err == nil {
				t.Errorf("compose accepted a bad `with` mapping (%s)", tc.with)
			}
		})
	}
}
