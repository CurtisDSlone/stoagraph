package stag_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// EvalArgs binds each `propose out: X` from args[X] — so one recipe can decide from several
// named arguments. This recipe gates arg `a` (a gate that must equal "pass") and arg `b` (a
// sink that must equal "ok"); swapping which input is bad changes the verdict, proving the
// two are bound DISTINCTLY from their named args.
func TestEvalArgsBindsNamedInputs(t *testing.T) {
	ra := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"pass"}}
	rb := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"ok"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "pa", Kind: stag.NodePropose, Out: "a"},
		{Id: "pb", Kind: stag.NodePropose, Out: "b"},
		{Id: "ga", Kind: stag.NodeGate, In: "a", Rule: &ra, RuleID: "ra"},
		{Id: "sb", Kind: stag.NodeSink, In: "b", Field: "f.b", Sensitivity: stag.SinkAuthoritative, Rule: &rb, RuleID: "rb", Actor: "x"},
	}}
	cases := []struct {
		a, b string
		want stag.Verdict
	}{
		{"pass", "ok", stag.Allow}, // both inputs satisfy their own rule
		{"nope", "ok", stag.Deny},  // a fails its gate -> Deny  (a bound from args["a"])
		{"pass", "bad", stag.Deny}, // b fails its sink -> Deny  (b bound from args["b"])
	}
	for _, c := range cases {
		if got := stag.EvalArgs(r, map[string]string{"a": c.a, "b": c.b}, "h").Verdict; got != c.want {
			t.Errorf("EvalArgs(a=%q,b=%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
	// Backward compat: single-arg Eval binds the ONE proposal to every propose. Here that
	// makes a=b="pass", so sink b (needs "ok") denies.
	if v := stag.Eval(r, "pass", "h").Verdict; v != stag.Deny {
		t.Errorf("single-arg Eval a=b=\"pass\": want Deny, got %v", v)
	}
}
