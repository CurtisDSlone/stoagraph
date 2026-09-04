package stag

import (
	"encoding/json"
	"testing"
)

// An `invoke` step AUTHORIZES a call; the executor carries it. Eval performs NO I/O:
// it resolves the call's arguments from slots, gates each one exactly as a sink does,
// and appends an AuthorizedCall. So the kernel stays a pure function of (recipe, args,
// hash) — replayable offline — while the product gains deterministic multi-tool
// sequencing with no model anywhere in the path.

func nsSafe() *ReleaseRule {
	return &ReleaseRule{Kind: RuleSetMembership, Set: []string{"dev", "staging"}}
}

// propose(ns) -> invoke(k8s.drain) -> invoke(k8s.status): two tools, one proposal.
func invokeRecipe() Recipe {
	return Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "ns"},
		{Id: "drain", Kind: NodeInvoke, Tool: "k8s.drain", ArgRules: map[string]ArgRule{"node": {Slot: "ns", Rule: nsSafe(), RuleID: "ns.safe"}}, Actor: "policy:platform"},
		{Id: "check", Kind: NodeInvoke, Tool: "k8s.status", ArgRules: map[string]ArgRule{"node": {Slot: "ns", Rule: nsSafe(), RuleID: "ns.safe"}}, Actor: "policy:platform"},
	}}
}

// The happy path: both calls are authorized, in source order, with args resolved from slots.
func TestInvokeAuthorizesInSourceOrder(t *testing.T) {
	res := Eval(invokeRecipe(), "dev", "h")
	if res.Verdict != Allow || res.Fault != "" {
		t.Fatalf("allowed sequence: %+v", res)
	}
	if len(res.Authorized) != 2 {
		t.Fatalf("want 2 authorized calls, got %d", len(res.Authorized))
	}
	if res.Authorized[0].Tool != "k8s.drain" || res.Authorized[1].Tool != "k8s.status" {
		t.Errorf("source order not preserved: %+v", res.Authorized)
	}
	if got := res.Authorized[0].Args["node"]; got != "dev" {
		t.Errorf("args must resolve from slots: node=%q, want %q", got, "dev")
	}
	for _, c := range res.Authorized {
		if c.StepID == "" {
			t.Error("every authorized call names the step that authorized it")
		}
	}
}

// The load-bearing property: an argument that does not release authorizes NOTHING.
// A recipe cannot emit a call whose arguments were not cleared by a rule.
func TestInvokeDeniedArgAuthorizesNothing(t *testing.T) {
	res := Eval(invokeRecipe(), "prod", "h")
	if res.Verdict != Deny {
		t.Errorf("unreleased arg must deny: %v", res.Verdict)
	}
	if len(res.Authorized) != 0 {
		t.Errorf("a denied recipe must authorize no call, got %d: %+v", len(res.Authorized), res.Authorized)
	}
	if len(res.Events) != 0 {
		t.Errorf("no crossing may be recorded for an unauthorized call: %d", len(res.Events))
	}
}

// An invoke is a sink that names a tool instead of a field: the step that clears the
// crossing is the step that records it (inv 2). One ReleaseEvent per gated argument.
func TestInvokeRecordsCrossingPerArgument(t *testing.T) {
	res := Eval(invokeRecipe(), "staging", "h")
	if len(res.Events) != 2 {
		t.Fatalf("want one crossing per authorized argument, got %d", len(res.Events))
	}
	seen := map[int64]bool{}
	for _, e := range res.Events {
		if e.SubjectClass != Untrusted || e.TargetClass != Authoritative {
			t.Errorf("crossing must be untrusted -> authoritative: %+v", e)
		}
		if e.RecipeHash != "h" || e.AuthorizingRule != "ns.safe" {
			t.Errorf("crossing must carry the recipe and the rule that cleared it: %+v", e)
		}
		if seen[e.Ordering] {
			t.Errorf("crossings must have distinct Ordering: %d", e.Ordering)
		}
		seen[e.Ordering] = true
	}
}

// Purity: the same inputs authorize the same calls, every time. This is what makes an
// invoke recipe replayable offline by an auditor.
func TestInvokeIsDeterministic(t *testing.T) {
	first := Eval(invokeRecipe(), "dev", "h")
	for i := 0; i < 32; i++ {
		got := Eval(invokeRecipe(), "dev", "h")
		if got.Verdict != first.Verdict || len(got.Authorized) != len(first.Authorized) {
			t.Fatalf("eval %d diverged: %+v vs %+v", i, got, first)
		}
		for j := range got.Authorized {
			a, b := got.Authorized[j], first.Authorized[j]
			if a.Tool != b.Tool || a.StepID != b.StepID || a.Ordinal != b.Ordinal {
				t.Fatalf("eval %d call %d diverged: %+v vs %+v", i, j, a, b)
			}
			for k, v := range b.Args {
				if a.Args[k] != v {
					t.Fatalf("eval %d call %d arg %q diverged: %q vs %q", i, j, k, a.Args[k], v)
				}
			}
		}
	}
}

// A branch may select WHICH sequence is authorized — branching is not lost by keeping
// the plan static, only branching on a RESULT is (that is the flagged v2 feature).
func TestInvokeBranchSelectsSequence(t *testing.T) {
	prod := ReleaseRule{Kind: RuleSetMembership, Set: []string{"prod"}}
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "ns"},
		{Id: "route", Kind: NodeBranch, In: "ns",
			Cases:   []Case{{Rule: &prod, Goto: "careful"}},
			Default: "quick"},
		{Id: "quick", Kind: NodeInvoke, Tool: "k8s.drain", ArgRules: map[string]ArgRule{"node": {Slot: "ns", Rule: nsSafe(), RuleID: "ns.safe"}}, Actor: "a", Goto: "done"},
		{Id: "done", Kind: NodeExit},
		{Id: "careful", Kind: NodeInvoke, Tool: "k8s.snapshot", ArgRules: map[string]ArgRule{"node": {Slot: "ns", Rule: &prod, RuleID: "ns.prod"}}, Actor: "a"},
	}}
	dev := Eval(r, "dev", "h")
	if dev.Verdict != Allow || len(dev.Authorized) != 1 || dev.Authorized[0].Tool != "k8s.drain" {
		t.Errorf("dev must authorize the quick path: %+v", dev.Authorized)
	}
	pd := Eval(r, "prod", "h")
	if pd.Verdict != Allow || len(pd.Authorized) != 1 || pd.Authorized[0].Tool != "k8s.snapshot" {
		t.Errorf("prod must authorize the careful path: %+v", pd.Authorized)
	}
}

// Fail closed on every structural defect: a severed slot, an absent rule, an unresolvable
// argument, a missing tool. None may authorize a call.
//
// "No arguments" is NOT a defect — see TestInvokeWithNoArgumentsIsAuthorizedByTheStep. A tool
// that takes none is authorized by the step being in the recipe.
func TestInvokeFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		step Step
	}{
		{"severed slot", Step{Id: "i", Kind: NodeInvoke, Tool: "t", ArgRules: map[string]ArgRule{"a": {Slot: "nope", Rule: nsSafe(), RuleID: "r"}}, Actor: "a"}},
		{"absent rule", Step{Id: "i", Kind: NodeInvoke, Tool: "t", ArgRules: map[string]ArgRule{"a": {Slot: "ns", RuleID: "r"}}, Actor: "a"}},
		{"empty tool", Step{Id: "i", Kind: NodeInvoke, ArgRules: map[string]ArgRule{"a": {Slot: "ns", Rule: nsSafe(), RuleID: "r"}}, Actor: "a"}},
	}
	for _, c := range cases {
		r := Recipe{Steps: []Step{{Id: "p", Kind: NodePropose, Out: "ns"}, c.step}}
		res := Eval(r, "dev", "h")
		if res.Verdict != Deny {
			t.Errorf("%s: must deny, got %v", c.name, res.Verdict)
		}
		if len(res.Authorized) != 0 {
			t.Errorf("%s: must authorize nothing, got %+v", c.name, res.Authorized)
		}
	}
}

// foreach x invoke is the ONE place an attacker-chosen list length multiplies
// author-written calls (64 elements x 3 invokes = 192 actions from one proposal).
// Everywhere else the count is fixed by the recipe source. Refused structurally.
func TestInvokeInsideForeachIsRefused(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "list"},
		{Id: "fe", Kind: NodeForeach, In: "list", As: "item"},
		{Id: "i", Kind: NodeInvoke, Tool: "k8s.drain", ArgRules: map[string]ArgRule{"node": {Slot: "item", Rule: nsSafe(), RuleID: "ns.safe"}}, Actor: "a"},
	}}
	res := Eval(r, `["dev","staging"]`, "h")
	if res.Fault == "" || res.Verdict != Deny {
		t.Errorf("invoke inside foreach must fault: %+v", res)
	}
	if len(res.Authorized) != 0 {
		t.Errorf("a faulted recipe authorizes nothing, got %d", len(res.Authorized))
	}
}

func TestNodeKindInvokeParse(t *testing.T) {
	k, err := ParseNodeKind("invoke")
	if err != nil || k != NodeInvoke || k.String() != "invoke" {
		t.Errorf("invoke node kind: k=%v err=%v str=%q", k, err, k.String())
	}
}

// A recipe with no invoke steps authorizes nothing and is byte-identical to before.
func TestNoInvokeNoAuthorized(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "v"},
		{Id: "s", Kind: NodeSink, In: "v", Field: "exec", Sensitivity: SinkAuthoritative, Rule: allowedRule(), RuleID: "r", Actor: "a"},
	}}
	res := Eval(r, "restart", "h")
	if res.Verdict != Allow || len(res.Authorized) != 0 || len(res.Events) != 1 {
		t.Errorf("non-invoke recipe changed: %+v", res)
	}
}

// The safety property over arbitrary input: every authorized call's arguments cleared
// the step's rule, and a denied verdict authorizes nothing.
func FuzzInvokeAuthorization(f *testing.F) {
	f.Add("dev")
	f.Add("prod")
	f.Add("")
	f.Add("dev\x00staging")
	r := invokeRecipe()
	rule := nsSafe()
	f.Fuzz(func(t *testing.T, ns string) {
		res := Eval(r, ns, "h")
		released := rule.Release(ns)
		if !released && len(res.Authorized) != 0 {
			t.Fatalf("ns=%q did not release but authorized %d calls", ns, len(res.Authorized))
		}
		if released && len(res.Authorized) != 2 {
			t.Fatalf("ns=%q released but authorized %d calls", ns, len(res.Authorized))
		}
		for _, c := range res.Authorized {
			for _, v := range c.Args {
				if !rule.Release(v) {
					t.Fatalf("authorized call carries an unreleased arg %q", v)
				}
			}
		}
		if res.Verdict == Deny && len(res.Authorized) != 0 {
			t.Fatalf("denied verdict must authorize nothing: %+v", res.Authorized)
		}
		// determinism under fuzz
		again := Eval(r, ns, "h")
		if len(again.Authorized) != len(res.Authorized) || again.Verdict != res.Verdict {
			t.Fatalf("ns=%q not deterministic", ns)
		}
	})
}

// Guard: AuthorizedCall must stay JSON-canonical, since the plan is shown to a human
// for review before execution and rides in the audit record.
func TestAuthorizedCallIsCanonical(t *testing.T) {
	res := Eval(invokeRecipe(), "dev", "h")
	b, err := json.Marshal(res.Authorized)
	if err != nil {
		t.Fatalf("authorized plan must marshal: %v", err)
	}
	if len(b) == 0 || string(b) == "null" {
		t.Error("authorized plan must serialize to a reviewable value")
	}
}

// A tool that takes NO ARGUMENTS is still a tool worth sequencing: restart, status, list. The
// first cut required at least one argument, which forced a recipe to pass a fake one purely to
// satisfy the check — putting a lie in the policy, and gating a value the tool never receives.
//
// An argumentless invoke is authorized by the STEP being in the recipe, exactly as an empty
// GateArg means "no arguments to judge; the route is the authorization". There is nothing to
// gate, so nothing is gated — and that is stated, not smuggled in behind a decorative rule.
func TestInvokeWithNoArgumentsIsAuthorizedByTheStep(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "v"},
		{Id: "restart", Kind: NodeInvoke, Tool: "k8s__restart_workload", Actor: "policy:x"},
	}}
	res := EvalArgs(r, map[string]string{"v": "anything"}, "h")
	if res.Verdict != Allow || res.Fault != "" {
		t.Fatalf("an argumentless invoke must authorize: %+v", res)
	}
	if len(res.Authorized) != 1 {
		t.Fatalf("want 1 authorized call, got %d", len(res.Authorized))
	}
	c := res.Authorized[0]
	if c.Tool != "k8s__restart_workload" {
		t.Errorf("tool: %q", c.Tool)
	}
	if len(c.Args) != 0 {
		t.Errorf("it must carry no arguments, got %+v", c.Args)
	}
}

// It still records a crossing: the call happens, and the audit must say so. There is simply no
// per-argument release to attach.
func TestArgumentlessInvokeStillRecordsTheCall(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "v"},
		{Id: "restart", Kind: NodeInvoke, Tool: "t", Actor: "policy:x"},
	}}
	res := EvalArgs(r, map[string]string{"v": "x"}, "h")
	if len(res.Authorized) != 1 {
		t.Fatal("must authorize")
	}
	// no arguments means no argument crossings — the call is authorized by the step
	if len(res.Events) != 0 {
		t.Errorf("no argument, no argument-crossing: %d events", len(res.Events))
	}
}

// A tool name is still required: an invoke naming nothing is a fault, not an argumentless call.
func TestInvokeStillNeedsATool(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "v"},
		{Id: "i", Kind: NodeInvoke, Actor: "a"},
	}}
	res := EvalArgs(r, map[string]string{"v": "x"}, "h")
	if res.Fault == "" || len(res.Authorized) != 0 {
		t.Errorf("an invoke with no tool must fault: %+v", res)
	}
}

// An AWAIT with no arguments is the common case for a status poll, and it still needs its
// condition — that is what makes it an await rather than a call in a loop.
func TestArgumentlessAwaitStillNeedsItsCondition(t *testing.T) {
	done := ReleaseRule{Kind: RuleSetMembership, Set: []string{"complete"}}
	ok := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "v"},
		{Id: "settle", Kind: NodeAwait, Tool: "k8s__rollout_status", Actor: "a",
			Until: &done, UntilID: "rollout.done", Attempts: 4, DelayMS: 1000},
	}}
	if res := EvalArgs(ok, map[string]string{"v": "x"}, "h"); len(res.Authorized) != 1 {
		t.Fatalf("an argumentless await must authorize: %+v", res)
	}
	bad := ok
	bad.Steps = append([]Step{}, ok.Steps...)
	bad.Steps[1].Until = nil
	if res := EvalArgs(bad, map[string]string{"v": "x"}, "h"); res.Fault == "" {
		t.Error("an await with no condition must still fault, arguments or not")
	}
}
