package stag

import "testing"

// PER-ARGUMENT RULES. An invoke's arguments are usually different KINDS of value — a target
// name, an operation, a payload. One rule checked against all of them cannot say which
// argument may be what: it degenerates into a flat bag of permitted strings that would clear
// a payload in the target's slot. Each argument therefore carries its own rule, and the rule
// states what that argument actually is.

func setRule(vals ...string) *ReleaseRule {
	return &ReleaseRule{Kind: RuleSetMembership, Set: vals}
}

// the shape the lab needs: three arguments, three different kinds of thing.
func perArgRecipe() Recipe {
	return Recipe{Steps: []Step{
		{Id: "p_img", Kind: NodePropose, Out: "image"},
		{Id: "p_op", Kind: NodePropose, Out: "op"},
		{Id: "p_val", Kind: NodePropose, Out: "value"},
		{Id: "fix", Kind: NodeInvoke, Tool: "fix_dockerfile", Actor: "policy:test",
			ArgRules: map[string]ArgRule{
				"image": {Slot: "image", Rule: setRule("badport"), RuleID: "image.this"},
				"op":    {Slot: "op", Rule: setRule("set_expose"), RuleID: "op.this"},
				"value": {Slot: "value", Rule: setRule("8080"), RuleID: "port.correct"},
			}},
	}}
}

func TestPerArgumentRulesClearEachArgument(t *testing.T) {
	res := EvalArgs(perArgRecipe(), map[string]string{
		"image": "badport", "op": "set_expose", "value": "8080"}, "h")
	if res.Verdict != Allow || res.Fault != "" {
		t.Fatalf("each argument satisfies its own rule: %+v", res)
	}
	if len(res.Authorized) != 1 {
		t.Fatalf("want 1 authorized call, got %d", len(res.Authorized))
	}
	a := res.Authorized[0]
	if a.Args["image"] != "badport" || a.Args["op"] != "set_expose" || a.Args["value"] != "8080" {
		t.Errorf("args must resolve per slot: %+v", a.Args)
	}
}

// THE POINT OF THE FEATURE: a value that is legal for ONE argument must not clear a DIFFERENT
// argument. Under a single shared rule these all passed, because the rule was the union.
func TestArgumentValuesAreNotInterchangeable(t *testing.T) {
	cases := []struct {
		name             string
		image, op, value string
	}{
		{"port in the image slot", "8080", "set_expose", "8080"},
		{"image name in the value slot", "badport", "set_expose", "badport"},
		{"op in the image slot", "set_expose", "set_expose", "8080"},
		{"value in the op slot", "badport", "8080", "8080"},
	}
	for _, c := range cases {
		res := EvalArgs(perArgRecipe(), map[string]string{
			"image": c.image, "op": c.op, "value": c.value}, "h")
		if res.Verdict != Deny {
			t.Errorf("%s: must deny, got %v", c.name, res.Verdict)
		}
		if len(res.Authorized) != 0 {
			t.Errorf("%s: must authorize nothing, got %+v", c.name, res.Authorized)
		}
	}
}

// All-or-nothing survives: one failing argument authorizes no call, even when the others pass.
func TestOneFailingArgumentAuthorizesNothing(t *testing.T) {
	res := EvalArgs(perArgRecipe(), map[string]string{
		"image": "badport", "op": "set_expose", "value": "9999"}, "h")
	if res.Verdict != Deny || len(res.Authorized) != 0 {
		t.Errorf("one bad argument: %+v", res)
	}
	if len(res.Events) != 0 {
		t.Errorf("an unauthorized call records no crossing: %d", len(res.Events))
	}
}

// Each cleared argument records its OWN crossing, naming the rule that cleared it — so the
// audit says which rule authorized which argument, not merely that the call was allowed.
func TestEachArgumentRecordsItsOwnRule(t *testing.T) {
	res := EvalArgs(perArgRecipe(), map[string]string{
		"image": "badport", "op": "set_expose", "value": "8080"}, "h")
	if len(res.Events) != 3 {
		t.Fatalf("want one crossing per argument, got %d", len(res.Events))
	}
	byField := map[string]string{}
	for _, e := range res.Events {
		byField[e.TargetField] = e.AuthorizingRule
	}
	want := map[string]string{
		"fix_dockerfile.image": "image.this",
		"fix_dockerfile.op":    "op.this",
		"fix_dockerfile.value": "port.correct",
	}
	for f, rule := range want {
		if byField[f] != rule {
			t.Errorf("%s: authorized by %q, want %q", f, byField[f], rule)
		}
	}
}

// Fail closed: an argument with no rule of its own never clears. Silence is not permission.
func TestArgumentWithoutARuleNeverClears(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "image"},
		{Id: "i", Kind: NodeInvoke, Tool: "t", Actor: "a",
			ArgRules: map[string]ArgRule{
				"image": {Slot: "image"}, // no Rule
			}},
	}}
	res := EvalArgs(r, map[string]string{"image": "badport"}, "h")
	if res.Verdict != Deny || len(res.Authorized) != 0 {
		t.Errorf("an argument with no rule must not clear: %+v", res)
	}
}

// An argument fed by a slot nothing bound never clears either.
func TestArgumentWithSeveredSlotNeverClears(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "image"},
		{Id: "i", Kind: NodeInvoke, Tool: "t", Actor: "a",
			ArgRules: map[string]ArgRule{
				"image": {Slot: "nothing_bound_this", Rule: setRule("badport"), RuleID: "r"},
			}},
	}}
	res := EvalArgs(r, map[string]string{"image": "badport"}, "h")
	if res.Verdict != Deny || len(res.Authorized) != 0 {
		t.Errorf("severed slot: %+v", res)
	}
}

// Determinism holds: the same inputs authorize the same call every time, and the crossings
// are recorded in a stable order regardless of Go's map iteration.
func TestPerArgumentIsDeterministic(t *testing.T) {
	args := map[string]string{"image": "badport", "op": "set_expose", "value": "8080"}
	first := EvalArgs(perArgRecipe(), args, "h")
	for i := 0; i < 32; i++ {
		got := EvalArgs(perArgRecipe(), args, "h")
		if got.Verdict != first.Verdict || len(got.Events) != len(first.Events) {
			t.Fatalf("run %d diverged", i)
		}
		for j := range got.Events {
			if got.Events[j].TargetField != first.Events[j].TargetField {
				t.Fatalf("run %d: crossing order not stable at %d", i, j)
			}
		}
	}
}

// The safety property over arbitrary input: no authorized call ever carries an argument that
// failed that argument's own rule.
func FuzzPerArgumentAuthorization(f *testing.F) {
	f.Add("badport", "set_expose", "8080")
	f.Add("8080", "set_expose", "8080")
	f.Add("badport", "badport", "badport")
	f.Add("", "", "")
	r := perArgRecipe()
	f.Fuzz(func(t *testing.T, image, op, value string) {
		res := EvalArgs(r, map[string]string{"image": image, "op": op, "value": value}, "h")
		okAll := image == "badport" && op == "set_expose" && value == "8080"
		if okAll && len(res.Authorized) != 1 {
			t.Fatalf("all three valid but authorized %d", len(res.Authorized))
		}
		if !okAll && len(res.Authorized) != 0 {
			t.Fatalf("image=%q op=%q value=%q authorized %d", image, op, value, len(res.Authorized))
		}
		for _, c := range res.Authorized {
			if c.Args["image"] != "badport" || c.Args["op"] != "set_expose" || c.Args["value"] != "8080" {
				t.Fatalf("authorized call carries an uncleared argument: %+v", c.Args)
			}
		}
	})
}
