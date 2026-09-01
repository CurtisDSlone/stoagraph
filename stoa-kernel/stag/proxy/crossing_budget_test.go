package proxy_test

// kw-test: the per-session crossing budget (Planning/34 §6.2) — reserve up to the limit then fail closed;
// a released reservation frees a slot; nil/limit<=0 is unlimited; concurrent-safe.

import (
	"sync"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

func TestCrossingBudgetReserveAndRelease(t *testing.T) {
	c := proxy.NewCrossingBudget(2)
	if !c.Reserve() || !c.Reserve() {
		t.Fatal("the first two reservations must succeed within the budget")
	}
	if c.Reserve() {
		t.Fatal("a reservation past the limit must FAIL (fail closed)")
	}
	c.Release() // a non-forwarded call gives its reservation back
	if !c.Reserve() {
		t.Fatal("after a release, one slot must free up")
	}
	if c.Reserve() {
		t.Fatal("still at the limit after re-reserving")
	}
}

func TestCrossingBudgetUnlimited(t *testing.T) {
	for _, c := range []*proxy.CrossingBudget{proxy.NewCrossingBudget(0), nil} {
		for i := 0; i < 10000; i++ {
			if !c.Reserve() {
				t.Fatalf("nil/zero budget means unlimited; reservation %d failed", i)
			}
		}
		c.Release() // must be a safe no-op (incl. nil receiver)
	}
}

// Exactly `limit` reservations may ever succeed at once, no matter how many goroutines race.
func TestCrossingBudgetConcurrentlySafe(t *testing.T) {
	const limit = 50
	c := proxy.NewCrossingBudget(limit)
	var granted int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Reserve() {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != limit {
		t.Fatalf("exactly %d reservations may be granted under contention; got %d", limit, granted)
	}
}
