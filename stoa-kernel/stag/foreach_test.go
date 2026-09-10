package stag_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

func allowedRule() *stag.ReleaseRule {
	return &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "scale", "clear"}}
}

// propose(list) -> foreach(as=item) -> authoritative sink gated by the allowed set.
func foreachRecipe() stag.Recipe {
	return stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "plan"},
		{Id: "fe", Kind: stag.NodeForeach, In: "plan", As: "item"},
		{Id: "apply", Kind: stag.NodeSink, In: "item", Field: "exec.action", Sensitivity: stag.SinkAuthoritative, Rule: allowedRule(), RuleID: "action.allowed", Actor: "policy:x"},
	}}
}

func TestForeachAllAllowed(t *testing.T) {
	r := foreachRecipe()
	res := stag.Eval(r, `["restart","scale"]`, "h")
	if res.Verdict != stag.Allow || res.Fault != "" {
		t.Fatalf("all-allowed batch: %+v", res)
	}
	if len(res.Events) != 2 {
		t.Fatalf("want 2 release events, got %d", len(res.Events))
	}
	seen := map[int64]bool{}
	for _, e := range res.Events {
		if e.SubjectClass != stag.Untrusted || e.RecipeHash != "h" {
			t.Errorf("event: %+v", e)
		}
		if seen[e.Ordering] {
			t.Errorf("release events must have distinct Ordering per element: %d", e.Ordering)
		}
		seen[e.Ordering] = true
	}
}

func TestForeachOneDeniedDeniesBatch(t *testing.T) {
	res := stag.Eval(foreachRecipe(), `["restart","bad_cmd"]`, "h")
	if res.Verdict != stag.Deny {
		t.Errorf("one denied element must deny the batch: %v", res.Verdict)
	}
	if len(res.Events) != 1 {
		t.Errorf("only the allowed element crosses: %d events", len(res.Events))
	}
}

func TestForeachEmptyList(t *testing.T) {
	res := stag.Eval(foreachRecipe(), `[]`, "h")
	if res.Verdict != stag.Allow || len(res.Events) != 0 || len(res.Sinks) != 0 {
		t.Errorf("empty list must be Allow with no crossings: %+v", res)
	}
}

func TestForeachFailsClosed(t *testing.T) {
	r := foreachRecipe()
	cases := []string{`not-json`, `[1,2]`, `{"a":1}`, `"just a string"`}
	for _, p := range cases {
		res := stag.Eval(r, p, "h")
		if res.Fault == "" || res.Verdict != stag.Deny || len(res.Events) != 0 {
			t.Errorf("proposal %q must fault: %+v", p, res)
		}
	}
	// over cap
	big, _ := json.Marshal(make([]string, stag.ForeachCap+1))
	if res := stag.Eval(r, string(big), "h"); res.Fault == "" || res.Verdict != stag.Deny {
		t.Errorf("over-cap list must fault: %+v", res)
	}
	// nested foreach in the body -> fault
	nested := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "plan"},
		{Id: "fe", Kind: stag.NodeForeach, In: "plan", As: "item"},
		{Id: "fe2", Kind: stag.NodeForeach, In: "item", As: "sub"},
		{Id: "apply", Kind: stag.NodeSink, In: "sub", Field: "x", Sensitivity: stag.SinkAuthoritative, Rule: allowedRule(), RuleID: "r", Actor: "a"},
	}}
	if res := stag.Eval(nested, `["[\"restart\"]"]`, "h"); res.Fault == "" {
		t.Errorf("nested foreach must fault: %+v", res)
	}
}

func TestNodeKindForeachParse(t *testing.T) {
	k, err := stag.ParseNodeKind("foreach")
	if err != nil || k != stag.NodeForeach || k.String() != "foreach" {
		t.Errorf("foreach node kind: k=%v err=%v str=%q", k, err, k.String())
	}
	if _, err := stag.ParseNodeKind("bogus"); err == nil {
		t.Error("unknown kind must still error")
	}
}

// regression: a non-foreach recipe evaluates exactly as before the refactor.
func TestNonForeachUnchanged(t *testing.T) {
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "v"},
		{Id: "s", Kind: stag.NodeSink, In: "v", Field: "exec", Sensitivity: stag.SinkAuthoritative, Rule: allowedRule(), RuleID: "r", Actor: "a"},
	}}
	res := stag.Eval(r, "restart", "h")
	if res.Verdict != stag.Allow || len(res.Events) != 1 || res.Events[0].Ordering != 1 {
		t.Errorf("non-foreach recipe changed: %+v", res)
	}
}

func FuzzForeach(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{})
	f.Add([]byte{3, 3, 3}) // all denied
	f.Add(make([]byte, stag.ForeachCap+5))
	vocab := []string{"restart", "scale", "clear", "NOPE"} // index 3 is denied
	r := foreachRecipe()
	f.Fuzz(func(t *testing.T, data []byte) {
		elems := make([]string, 0, len(data))
		for _, b := range data {
			elems = append(elems, vocab[int(b)%4])
		}
		arr, err := json.Marshal(elems)
		if err != nil {
			t.Skip()
		}
		res := stag.Eval(r, string(arr), "h")

		if len(elems) > stag.ForeachCap {
			if res.Fault == "" || res.Verdict != stag.Deny {
				t.Fatalf("over-cap must fault: %d elems", len(elems))
			}
			return
		}
		// recompute independently
		allAllowed, wantEvents := true, 0
		for _, e := range elems {
			if strings.HasPrefix(e, "NOPE") { // the one denied token
				allAllowed = false
			} else {
				wantEvents++
			}
		}
		want := stag.Deny
		if allAllowed {
			want = stag.Allow
		}
		if res.Verdict != want {
			t.Fatalf("verdict %v, want %v (elems %v)", res.Verdict, want, elems)
		}
		if len(res.Events) != wantEvents {
			t.Fatalf("events %d, want %d (elems %v)", len(res.Events), wantEvents, elems)
		}
		if res2 := stag.Eval(r, string(arr), "h"); !reflect.DeepEqual(res, res2) {
			t.Fatalf("nondeterministic")
		}
	})
}
