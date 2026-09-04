package stag

import "testing"

// AWAIT — "do not proceed until this holds."
//
// The kernel does NOT poll: that would be I/O, and Eval must stay a pure function of the recipe
// and the arguments so an authorization can be replayed offline. An `await` step AUTHORIZES a
// bounded poll — the tool, the arguments, the rule the output must satisfy, and how many times
// and how often it may be tried — and the executor performs it.
//
// Every bound is author-unraisable. A recipe cannot ask for more attempts or a longer wait than
// the kernel permits, because attempts x delay is wall-clock an agent can spend by triggering
// the sequence, and a step that can wait forever is a step that never fails closed.

func awaitRule() *ReleaseRule {
	return &ReleaseRule{Kind: RuleSetMembership, Set: []string{"settled"}}
}

func awaitRecipe() Recipe {
	return Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "node"},
		{Id: "settle", Kind: NodeAwait, Tool: "k8s__pods_on_node", Actor: "policy:drain",
			ArgRules: map[string]ArgRule{
				"node": {Slot: "node", Rule: &ReleaseRule{Kind: RuleSetMembership, Set: []string{"kind-worker"}}, RuleID: "node.worker"},
			},
			Until: awaitRule(), UntilID: "pods.none", Attempts: 6, DelayMS: 5000},
	}}
}

// An await authorizes a POLL: the same shape as an authorized call, plus the condition and the
// bounds the executor must honour.
func TestAwaitAuthorizesABoundedPoll(t *testing.T) {
	res := EvalArgs(awaitRecipe(), map[string]string{"node": "kind-worker"}, "h")
	if res.Verdict != Allow || res.Fault != "" {
		t.Fatalf("a valid await must authorize: %+v", res)
	}
	if len(res.Authorized) != 1 {
		t.Fatalf("want 1 authorized poll, got %d", len(res.Authorized))
	}
	a := res.Authorized[0]
	if a.Tool != "k8s__pods_on_node" || a.Args["node"] != "kind-worker" {
		t.Errorf("poll target: %+v", a)
	}
	if a.Until == nil || a.UntilID != "pods.none" {
		t.Errorf("an await must carry the condition its output has to satisfy: %+v", a)
	}
	if a.Attempts != 6 || a.DelayMS != 5000 {
		t.Errorf("an await must carry its bounds: attempts=%d delay=%d", a.Attempts, a.DelayMS)
	}
}

// An ordinary invoke carries no condition: the executor must be able to tell a poll from a call.
func TestInvokeCarriesNoUntil(t *testing.T) {
	rule := ReleaseRule{Kind: RuleSetMembership, Set: []string{"kind-worker"}}
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "node"},
		{Id: "i", Kind: NodeInvoke, Tool: "t", Actor: "a",
			ArgRules: map[string]ArgRule{"node": {Slot: "node", Rule: &rule, RuleID: "r"}}},
	}}
	res := EvalArgs(r, map[string]string{"node": "kind-worker"}, "h")
	if len(res.Authorized) != 1 {
		t.Fatal("invoke must authorize")
	}
	if res.Authorized[0].Until != nil || res.Authorized[0].Attempts != 0 {
		t.Error("an invoke is one call, not a poll: it must carry no condition and no attempts")
	}
}

// The BOUNDS ARE THE KERNEL'S. A recipe asking for more attempts than the cap is a FAULT, not a
// quietly-clamped value: an author who wrote 1000 attempts believes they will get 1000, and
// silently giving them 32 is a policy that does not do what it says.
func TestAwaitBoundsAreAuthorUnraisable(t *testing.T) {
	cases := []struct {
		name              string
		attempts, delayMS int
	}{
		{"over the attempt cap", awaitAttemptCap + 1, 1000},
		{"over the delay cap", 3, awaitDelayCapMS + 1},
		{"over the total wall-clock cap", awaitAttemptCap, awaitDelayCapMS},
		{"zero attempts", 0, 1000},
		{"negative attempts", -1, 1000},
		{"negative delay", 3, -1},
	}
	for _, c := range cases {
		r := awaitRecipe()
		r.Steps[1].Attempts, r.Steps[1].DelayMS = c.attempts, c.delayMS
		res := EvalArgs(r, map[string]string{"node": "kind-worker"}, "h")
		if res.Fault == "" || res.Verdict != Deny {
			t.Errorf("%s (attempts=%d delay=%d): must fault, got %+v", c.name, c.attempts, c.delayMS, res)
		}
		if len(res.Authorized) != 0 {
			t.Errorf("%s: a faulted recipe authorizes nothing", c.name)
		}
	}
}

// An await with no condition is not an await. Fail closed rather than degenerate into an
// unconditional poll that always "succeeds".
func TestAwaitWithoutAConditionFaults(t *testing.T) {
	r := awaitRecipe()
	r.Steps[1].Until = nil
	res := EvalArgs(r, map[string]string{"node": "kind-worker"}, "h")
	if res.Fault == "" || len(res.Authorized) != 0 {
		t.Errorf("an await with no until-condition must fault: %+v", res)
	}
}

// The argument rules still apply: a poll is an authorized call and its arguments are gated
// exactly as an invoke's are.
func TestAwaitArgumentsAreStillGated(t *testing.T) {
	res := EvalArgs(awaitRecipe(), map[string]string{"node": "kind-control-plane"}, "h")
	if res.Verdict != Deny || len(res.Authorized) != 0 {
		t.Errorf("an await must not authorize a poll of an ungated target: %+v", res)
	}
}

// Determinism holds: the same inputs authorize the same poll with the same bounds.
func TestAwaitIsDeterministic(t *testing.T) {
	args := map[string]string{"node": "kind-worker"}
	first := EvalArgs(awaitRecipe(), args, "h")
	for i := 0; i < 16; i++ {
		got := EvalArgs(awaitRecipe(), args, "h")
		if got.Verdict != first.Verdict || len(got.Authorized) != len(first.Authorized) {
			t.Fatalf("run %d diverged", i)
		}
		if got.Authorized[0].Attempts != first.Authorized[0].Attempts ||
			got.Authorized[0].DelayMS != first.Authorized[0].DelayMS {
			t.Fatalf("run %d: bounds not stable", i)
		}
	}
}

// An await inside a foreach is refused for the same reason an invoke is — and more so: an
// attacker-chosen list length would multiply not just the calls but the WAITING.
func TestAwaitInsideForeachIsRefused(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "list"},
		{Id: "fe", Kind: NodeForeach, In: "list", As: "item"},
		{Id: "a", Kind: NodeAwait, Tool: "t", Actor: "x",
			ArgRules: map[string]ArgRule{"n": {Slot: "item", Rule: awaitRule(), RuleID: "r"}},
			Until:    awaitRule(), UntilID: "r", Attempts: 3, DelayMS: 1000},
	}}
	res := Eval(r, `["settled","settled"]`, "h")
	if res.Fault == "" || len(res.Authorized) != 0 {
		t.Errorf("await inside foreach must fault: %+v", res)
	}
}

func TestNodeKindAwaitParse(t *testing.T) {
	k, err := ParseNodeKind("await")
	if err != nil || k != NodeAwait || k.String() != "await" {
		t.Errorf("await node kind: k=%v err=%v str=%q", k, err, k.String())
	}
}

// The bounds hold over arbitrary input: an await either authorizes a poll within the kernel's
// limits, or authorizes nothing at all. There is no combination that yields an unbounded wait.
func FuzzAwaitBounds(f *testing.F) {
	f.Add(6, 5000)
	f.Add(0, 0)
	f.Add(awaitAttemptCap, awaitDelayCapMS)
	f.Add(-1, -1)
	f.Add(1<<30, 1<<30)
	f.Fuzz(func(t *testing.T, attempts, delayMS int) {
		r := awaitRecipe()
		r.Steps[1].Attempts, r.Steps[1].DelayMS = attempts, delayMS
		res := EvalArgs(r, map[string]string{"node": "kind-worker"}, "h")

		inBounds := attempts >= 1 && attempts <= awaitAttemptCap &&
			delayMS >= 0 && delayMS <= awaitDelayCapMS &&
			attempts*delayMS <= awaitTotalCapMS && attempts*delayMS >= 0 // guard overflow

		if !inBounds {
			if len(res.Authorized) != 0 {
				t.Fatalf("attempts=%d delay=%d is out of bounds but authorized %d",
					attempts, delayMS, len(res.Authorized))
			}
			return
		}
		if len(res.Authorized) != 1 {
			t.Fatalf("attempts=%d delay=%d is in bounds but authorized %d", attempts, delayMS, len(res.Authorized))
		}
		a := res.Authorized[0]
		if a.Attempts > awaitAttemptCap || a.DelayMS > awaitDelayCapMS ||
			a.Attempts*a.DelayMS > awaitTotalCapMS {
			t.Fatalf("an authorized poll exceeded the kernel's bounds: attempts=%d delay=%d", a.Attempts, a.DelayMS)
		}
	})
}
