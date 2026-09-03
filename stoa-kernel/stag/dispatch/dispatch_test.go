package dispatch

import (
	"context"
	"errors"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// The executor is TRANSPORT. Everything load-bearing about these tests is the same
// sentence: authorizing a call is not authority to make it. Every call the kernel
// authorized is re-crossed through the gate against that tool's OWN route and recipe,
// so a recipe can never launder an action by naming it.

// a Decider stub standing in for proxy.Gate.Decide, recording what it was asked.
type stubGate struct {
	seen     []proxy.ToolCall
	decide   func(proxy.ToolCall) proxy.Decision
	callErrs map[string]error
}

func (g *stubGate) Decide(_ context.Context, c proxy.ToolCall) proxy.Decision {
	g.seen = append(g.seen, c)
	return g.decide(c)
}

func allowAll(c proxy.ToolCall) proxy.Decision {
	return proxy.Decision{Tool: c.Tool, Verdict: stag.Allow, Forward: true}
}

type stubTransport struct {
	made []string
	err  map[string]error
}

func (t *stubTransport) Call(_ context.Context, c proxy.ToolCall) (string, error) {
	t.made = append(t.made, c.Tool)
	if e, ok := t.err[c.Tool]; ok {
		return "", e
	}
	return "ok:" + c.Tool, nil
}

func plan() []stag.AuthorizedCall {
	return []stag.AuthorizedCall{
		{StepID: "drain", Tool: "k8s.drain", Args: map[string]string{"node": "dev"}, Ordinal: 1},
		{StepID: "check", Tool: "k8s.status", Args: map[string]string{"node": "dev"}, Ordinal: 2},
		{StepID: "tell", Tool: "notify", Args: map[string]string{"channel": "ops"}, Ordinal: 3},
	}
}

// EVERY authorized call re-crosses the gate before it is made. This is the property the
// whole design rests on: the authorizing recipe's clearance is not the target's clearance.
func TestEveryCallReCrossesTheGate(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &stubTransport{}
	res := Execute(context.Background(), g, tr, plan())
	if len(g.seen) != 3 {
		t.Fatalf("every authorized call must re-cross the gate: %d of 3", len(g.seen))
	}
	for i, want := range []string{"k8s.drain", "k8s.status", "notify"} {
		if g.seen[i].Tool != want {
			t.Errorf("call %d: gate saw %q, want %q", i, g.seen[i].Tool, want)
		}
	}
	if len(res.Steps) != 3 || !res.Complete {
		t.Errorf("all-allowed plan must complete: %+v", res)
	}
}

// A call the target's OWN policy denies is not made, even though the authorizing recipe
// cleared it. A recipe cannot launder an action by naming it in an invoke.
func TestTargetPolicyDeniesDespiteAuthorization(t *testing.T) {
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		if c.Tool == "k8s.status" {
			return proxy.Decision{Tool: c.Tool, Verdict: stag.Deny, Forward: false}
		}
		return allowAll(c)
	}}
	tr := &stubTransport{}
	res := Execute(context.Background(), g, tr, plan())
	for _, m := range tr.made {
		if m == "k8s.status" {
			t.Fatal("a call the gate refused must never reach the transport")
		}
	}
	if res.Complete {
		t.Error("a denied step must not report a complete sequence")
	}
}

// Halt, no rollback: steps before the denial already happened and stay happened. The
// result says exactly where it stopped — the gate never claims a transactional
// guarantee it cannot provide over arbitrary third-party tools.
func TestHaltNoRollback(t *testing.T) {
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		if c.Tool == "k8s.status" {
			return proxy.Decision{Tool: c.Tool, Verdict: stag.Deny, Forward: false}
		}
		return allowAll(c)
	}}
	tr := &stubTransport{}
	res := Execute(context.Background(), g, tr, plan())

	if len(tr.made) != 1 || tr.made[0] != "k8s.drain" {
		t.Errorf("steps before the halt must have run: %v", tr.made)
	}
	if len(g.seen) != 2 {
		t.Errorf("the gate must not be consulted past the halt: %d", len(g.seen))
	}
	if res.HaltedAt != "check" {
		t.Errorf("the result must name the step it halted on: %q", res.HaltedAt)
	}
	if len(res.Steps) != 2 {
		t.Errorf("the result must record what ran and what refused: %d", len(res.Steps))
	}
	if res.Steps[0].Made != true || res.Steps[1].Made != false {
		t.Errorf("per-step outcome wrong: %+v", res.Steps)
	}
}

// An escalation halts the sequence too: a call awaiting a human is not a call made.
func TestEscalationHalts(t *testing.T) {
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		if c.Tool == "k8s.drain" {
			return proxy.Decision{Tool: c.Tool, Verdict: stag.Escalate, Forward: false, ApprovalID: "ap-1"}
		}
		return allowAll(c)
	}}
	tr := &stubTransport{}
	res := Execute(context.Background(), g, tr, plan())
	if len(tr.made) != 0 {
		t.Error("nothing may be made when the first step escalates")
	}
	if res.HaltedAt != "drain" || res.Complete {
		t.Errorf("escalation must halt at the step: %+v", res)
	}
	if res.Steps[0].ApprovalID != "ap-1" {
		t.Error("the result must carry the approval id so a caller can poll it")
	}
}

// A transport failure halts as well, and is reported honestly as a failure to make the
// call — NOT as a policy denial. Conflating the two would misreport the audit.
func TestTransportFailureHaltsAndIsDistinct(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &stubTransport{err: map[string]error{"k8s.status": errors.New("downstream refused")}}
	res := Execute(context.Background(), g, tr, plan())
	if res.Complete || res.HaltedAt != "check" {
		t.Errorf("a transport failure must halt: %+v", res)
	}
	if res.Steps[1].Verdict != stag.Allow {
		t.Error("the gate ALLOWED it; the failure was transport, and the record must say so")
	}
	if res.Steps[1].Error == "" {
		t.Error("a transport failure must be recorded as an error")
	}
	if res.Steps[1].Made {
		t.Error("a call that errored did not succeed")
	}
	if len(tr.made) != 2 {
		t.Errorf("execution must stop after the failing call: %v", tr.made)
	}
}

// An empty plan is a no-op that completes: a recipe with no invoke authorizes nothing
// and the executor has nothing to do.
func TestEmptyPlanCompletes(t *testing.T) {
	g := &stubGate{decide: allowAll}
	res := Execute(context.Background(), g, nil, nil)
	if !res.Complete || len(res.Steps) != 0 || len(g.seen) != 0 {
		t.Errorf("empty plan: %+v", res)
	}
}

// Fail closed on a malformed plan: a call with no tool is never made.
func TestMalformedCallRefused(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &stubTransport{}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{{StepID: "bad", Tool: ""}})
	if len(tr.made) != 0 || res.Complete {
		t.Errorf("a call with no tool must be refused: %+v", res)
	}
}

// A cancelled context stops the sequence without making further calls.
func TestContextCancellationHalts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		cancel() // cancel after the first decision
		return allowAll(c)
	}}
	tr := &stubTransport{}
	res := Execute(ctx, g, tr, plan())
	if res.Complete {
		t.Error("a cancelled sequence is not complete")
	}
	if len(tr.made) > 1 {
		t.Errorf("cancellation must stop the sequence: %v", tr.made)
	}
}

// The executor passes the AUTHORIZED arguments verbatim: it may not add, drop or edit
// an argument the kernel cleared.
func TestArgumentsForwardedVerbatim(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &stubTransport{}
	Execute(context.Background(), g, tr, plan())
	got := g.seen[0].Args
	if len(got) != 1 || got["node"] != "dev" {
		t.Errorf("authorized args must reach the gate verbatim: %+v", got)
	}
}
