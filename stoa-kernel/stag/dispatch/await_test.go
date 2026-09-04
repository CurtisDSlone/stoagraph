package dispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// The executor performs the poll the kernel authorized: call, test the OUTPUT against the
// condition, wait, repeat — until it passes or the attempts run out.
//
// The output is read ONLY to decide continue-or-halt. It never becomes an argument to a later
// call and never reaches a sink: a downstream's response is external untrusted content, and
// letting it parameterize a subsequent action would be a new injection path INTO the gate.

func settledRule() *stag.ReleaseRule {
	return &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"settled"}}
}

func awaitCall(attempts, delayMS int) stag.AuthorizedCall {
	return stag.AuthorizedCall{
		StepID: "settle", Tool: "check", Args: map[string]string{"node": "n1"},
		Until: settledRule(), UntilID: "settled", Attempts: attempts, DelayMS: delayMS,
	}
}

// a transport whose output changes after N calls, so a poll can converge
type pollTransport struct {
	calls    int
	settleAt int
	err      error
}

func (p *pollTransport) Call(_ context.Context, _ proxy.ToolCall) (string, error) {
	p.calls++
	if p.err != nil {
		return "", p.err
	}
	if p.calls >= p.settleAt {
		return "settled", nil
	}
	return "pending", nil
}

// The poll stops as soon as the condition holds — it does not burn its remaining attempts.
func TestAwaitStopsWhenTheConditionHolds(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 3}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(6, 1)})
	if !res.Complete {
		t.Fatalf("a converging poll must complete: %+v", res)
	}
	if tr.calls != 3 {
		t.Errorf("must stop at the first passing attempt, made %d calls", tr.calls)
	}
	if res.Steps[0].Attempts != 3 {
		t.Errorf("the record must say how many attempts it took: %d", res.Steps[0].Attempts)
	}
}

// EXHAUSTION HALTS. A condition that never holds stops the sequence — the whole point of an
// await is that later steps do not run until it is true.
func TestAwaitExhaustionHalts(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 999} // never settles
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{
		awaitCall(4, 1),
		{StepID: "after", Tool: "later", Args: map[string]string{"a": "b"}},
	})
	if res.Complete {
		t.Fatal("an unmet condition must not report a complete sequence")
	}
	if res.HaltedAt != "settle" {
		t.Errorf("must halt on the await step: %q", res.HaltedAt)
	}
	if tr.calls != 4 {
		t.Errorf("must use exactly its attempts, made %d", tr.calls)
	}
	if len(res.Steps) != 1 {
		t.Errorf("nothing after the await may run: %d steps", len(res.Steps))
	}
}

// EVERY attempt re-crosses the gate. A poll is not a licence to call a tool repeatedly without
// judgment: the budget must meter it, and a revocation mid-poll must stop it.
func TestEveryAttemptReCrossesTheGate(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 3}
	Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(6, 1)})
	if len(g.seen) != 3 {
		t.Errorf("each attempt must re-cross the gate: %d crossings for 3 attempts", len(g.seen))
	}
}

// A gate refusal mid-poll halts immediately — it does not keep polling in the hope of a
// different verdict. The verdict is deterministic; retrying it is pointless and looks like
// an attempt to wear the gate down.
func TestGateRefusalMidPollHaltsImmediately(t *testing.T) {
	n := 0
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		n++
		if n >= 2 {
			return proxy.Decision{Tool: c.Tool, Verdict: stag.Deny, Forward: false}
		}
		return allowAll(c)
	}}
	tr := &pollTransport{settleAt: 999}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(8, 1)})
	if res.Complete || res.HaltedAt != "settle" {
		t.Errorf("a refusal mid-poll must halt: %+v", res)
	}
	if tr.calls != 1 {
		t.Errorf("no further attempt may be made after a refusal: %d", tr.calls)
	}
}

// A transport failure mid-poll halts too, and is recorded as an error rather than as an unmet
// condition — the two are different and the audit must not conflate them.
func TestTransportFailureMidPollHalts(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{err: errors.New("downstream gone")}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(5, 1)})
	if res.Complete {
		t.Fatal("a failing poll must halt")
	}
	if res.Steps[0].Error == "" {
		t.Error("a transport failure must be recorded as an error, not as an unmet condition")
	}
}

// The DELAY is honoured, so a poll cannot become a hot loop against a downstream.
func TestAwaitHonoursItsInterval(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 3}
	start := time.Now()
	Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(6, 40)})
	// 3 attempts => 2 waits
	if el := time.Since(start); el < 60*time.Millisecond {
		t.Errorf("the interval must be honoured between attempts: %v", el)
	}
}

// A cancelled context stops a poll promptly rather than sleeping out its attempts.
func TestAwaitStopsOnCancellation(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 999}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := Execute(ctx, g, tr, []stag.AuthorizedCall{awaitCall(32, 1000)})
	if res.Complete {
		t.Error("a cancelled poll is not complete")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("cancellation must stop the poll promptly, took %v", el)
	}
}

// An ordinary call is unaffected: no condition means one attempt, exactly as before.
func TestOrdinaryCallIsStillOneAttempt(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &pollTransport{settleAt: 999}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{
		{StepID: "one", Tool: "t", Args: map[string]string{"a": "b"}}})
	if !res.Complete || tr.calls != 1 {
		t.Errorf("an invoke is one call: complete=%v calls=%d", res.Complete, tr.calls)
	}
}
