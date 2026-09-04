package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// ADVERSARIAL AWAIT. A poll is the one construct that repeats, so it is where a bound that is
// merely stated rather than enforced would show up: a tool that starts failing partway through,
// a revocation that must reach a poll already running, and wall-clock spent by an agent that
// triggers many sequences at once.

// a transport whose behaviour CHANGES partway through the poll
type flakyTransport struct {
	mu       sync.Mutex
	calls    int
	failFrom int    // start returning an error from this call onward
	settleAt int    // return the settling value from this call onward
	value    string // what "settled" looks like
}

func (f *flakyTransport) Call(_ context.Context, _ proxy.ToolCall) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failFrom > 0 && f.calls >= f.failFrom {
		return "", errors.New("downstream went away mid-poll")
	}
	if f.settleAt > 0 && f.calls >= f.settleAt {
		return f.value, nil
	}
	return "pending", nil
}

func (f *flakyTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// A tool that starts FAILING partway through a poll halts the sequence, and is recorded as a
// transport error — not as an unmet condition. The distinction matters: "the world never
// reached this state" and "we could not find out" are different facts for an operator.
func TestAwaitToolFailingMidPollIsAnErrorNotUnmet(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &flakyTransport{failFrom: 3}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(8, 1)})

	if res.Complete {
		t.Fatal("a poll whose tool failed must halt")
	}
	st := res.Steps[0]
	if st.Error == "" {
		t.Error("a mid-poll transport failure must be recorded as an Error")
	}
	if st.Unmet {
		t.Error("a tool that FAILED is not the same as a condition that was never met")
	}
	if st.Made {
		t.Error("a poll that ended in failure did not succeed")
	}
	if tr.count() != 3 {
		t.Errorf("must stop at the failing attempt, made %d calls", tr.count())
	}
}

// A tool that RECOVERS still only gets the attempts it was authorized: recovery does not
// replenish the budget.
func TestAwaitRecoveryDoesNotReplenishAttempts(t *testing.T) {
	g := &stubGate{decide: allowAll}
	// settles on call 9, but only 4 attempts are authorized
	tr := &flakyTransport{settleAt: 9, value: "settled"}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(4, 1)})
	if res.Complete {
		t.Fatal("the condition is not reachable within the authorized attempts")
	}
	if !res.Steps[0].Unmet {
		t.Error("exhausting attempts is UNMET")
	}
	if tr.count() != 4 {
		t.Errorf("exactly the authorized attempts, got %d", tr.count())
	}
}

// REVOCATION MID-POLL. A session withdrawn while a poll is running must stop it — a poll that
// outlived its binding would be authority surviving its own revocation. The gate is consulted
// on every attempt precisely so this reaches a poll already in flight.
func TestRevocationMidPollStopsIt(t *testing.T) {
	live := true
	var mu sync.Mutex
	g := &stubGate{decide: func(c proxy.ToolCall) proxy.Decision {
		mu.Lock()
		defer mu.Unlock()
		if !live {
			return proxy.Decision{Tool: c.Tool, Verdict: stag.Deny, Forward: false,
				Fault: "session revoked"}
		}
		return allowAll(c)
	}}
	tr := &flakyTransport{settleAt: 999} // never settles on its own
	go func() {
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		live = false
		mu.Unlock()
	}()
	start := time.Now()
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(32, 20)})
	if res.Complete {
		t.Fatal("a revoked session must not complete a poll")
	}
	// 32 attempts x 20ms would be ~640ms; revocation must cut it far shorter
	if el := time.Since(start); el > 400*time.Millisecond {
		t.Errorf("revocation must reach a poll already running, took %v", el)
	}
	if tr.count() >= 32 {
		t.Errorf("the poll must have been cut short, made %d attempts", tr.count())
	}
}

// The WALL-CLOCK an await can consume is bounded by its own authorization, and that bound holds
// however many polls run at once: N concurrent sequences cost N x the bound, never more. The
// per-sequence bound is what the kernel caps; the aggregate is what the session budget meters.
func TestConcurrentPollsEachHonourTheirOwnBound(t *testing.T) {
	const seqs = 8
	var wg sync.WaitGroup
	counts := make([]int, seqs)
	start := time.Now()
	for i := 0; i < seqs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g := &stubGate{decide: allowAll}
			tr := &flakyTransport{settleAt: 999}
			Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(4, 10)})
			counts[i] = tr.count()
		}(i)
	}
	wg.Wait()
	for i, c := range counts {
		if c != 4 {
			t.Errorf("sequence %d made %d attempts, want exactly its authorized 4", i, c)
		}
	}
	// concurrency must not serialize into 8x the wall-clock of one
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("concurrent polls must not serialize: %v", el)
	}
}

// A poll that is cancelled BETWEEN attempts stops there rather than making one more call.
func TestCancellationBetweenAttemptsMakesNoFurtherCall(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &flakyTransport{settleAt: 999}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(25 * time.Millisecond); cancel() }()
	Execute(ctx, g, tr, []stag.AuthorizedCall{awaitCall(32, 20)})
	n := tr.count()
	time.Sleep(60 * time.Millisecond)
	if tr.count() != n {
		t.Errorf("no call may be made after cancellation: %d -> %d", n, tr.count())
	}
}

// An await whose condition is met on the LAST permitted attempt still succeeds — the bound is
// "at most N", not "fewer than N".
func TestAwaitSucceedsOnTheFinalAttempt(t *testing.T) {
	g := &stubGate{decide: allowAll}
	tr := &flakyTransport{settleAt: 4, value: "settled"}
	res := Execute(context.Background(), g, tr, []stag.AuthorizedCall{awaitCall(4, 1)})
	if !res.Complete {
		t.Fatalf("meeting the condition on the last attempt must succeed: %+v", res)
	}
	if res.Steps[0].Attempts != 4 {
		t.Errorf("attempts: %d", res.Steps[0].Attempts)
	}
}
