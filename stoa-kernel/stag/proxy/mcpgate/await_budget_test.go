package mcpgate_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// THE BUDGET IS THE AGGREGATE BOUND. The kernel caps what ONE await may spend (32 attempts, 30s
// apart, 5 minutes total). It does not and cannot cap how many sequences an agent triggers — so
// the per-session crossing budget is what bounds the total, and every poll attempt must consume
// one. A poll that reserved a single crossing and then made 32 calls would be a hole straight
// through the leakage bound the budget exists to enforce.
func TestEveryPollAttemptConsumesACrossing(t *testing.T) {
	b := proxy.NewCrossingBudget(5)
	// simulate a poll: each attempt reserves before it is decided
	made := 0
	for i := 0; i < 32; i++ {
		if !b.Reserve() {
			break
		}
		made++
	}
	if made != 5 {
		t.Fatalf("a budget of 5 must permit exactly 5 attempts, got %d", made)
	}
	if b.Reserve() {
		t.Error("an exhausted budget must refuse further attempts")
	}
}

// A refused attempt RETURNS its reservation: only actual crossings count against the bound.
func TestRefusedAttemptReturnsItsReservation(t *testing.T) {
	b := proxy.NewCrossingBudget(2)
	if !b.Reserve() {
		t.Fatal("first reserve")
	}
	b.Release() // the attempt did not cross after all
	if !b.Reserve() || !b.Reserve() {
		t.Error("a released reservation must be reusable")
	}
	if b.Reserve() {
		t.Error("and the bound must still hold at 2")
	}
}

// The budget is shared across an agent's reconnects, so triggering many sequences cannot mint
// fresh allowance: a nil budget is unlimited, but a real one is per BOUND SESSION.
func TestBudgetIsNotResetByANewGate(t *testing.T) {
	b := proxy.NewCrossingBudget(3)
	g1 := proxy.Gate{Budget: b}
	g2 := proxy.Gate{Budget: b} // a second gating server for the same bound token
	for i := 0; i < 3; i++ {
		if !g1.Budget.Reserve() {
			t.Fatalf("reserve %d", i)
		}
	}
	if g2.Budget.Reserve() {
		t.Error("a second gating server must share the bound, not reset it")
	}
}
