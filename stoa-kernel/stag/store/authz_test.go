package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

func authzStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The load-bearing cycle: mint, find, spend, gone.
func TestGrantMintLookupBurn(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	g := proxy.Grant{Fingerprint: "fp-1", Tool: "lab__fix", Source: "policy:lab_repair_badport", Session: "s1"}
	if err := s.Mint(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Redeem(ctx, "fp-1", "s1")
	if err != nil || !ok {
		t.Fatalf("a minted grant must be redeemable by its own session: ok=%v err=%v", ok, err)
	}
	if got.Source != g.Source || got.Tool != g.Tool {
		t.Errorf("grant round-trip: %+v", got)
	}
	// redeeming CLAIMS it: the same grant cannot be redeemed twice
	if _, ok, _ := s.Redeem(ctx, "fp-1", "s1"); ok {
		t.Error("a redeemed grant must be gone (replay denied)")
	}
}

// An unminted fingerprint is not a grant, and that is not an error — it is the normal answer
// for every call that was never authorized.
func TestUnknownFingerprintIsNotAGrant(t *testing.T) {
	s := authzStore(t)
	g, ok, err := s.Redeem(context.Background(), "never-minted", "s1")
	if err != nil || ok || g.Fingerprint != "" {
		t.Errorf("unknown fingerprint: g=%+v ok=%v err=%v", g, ok, err)
	}
}

// Re-minting REPLACES rather than stacks: a grant is permission for one call, not a counter.
// Two outstanding copies would let a sequence spend one and leave the other live.
func TestReMintDoesNotStack(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	g := proxy.Grant{Fingerprint: "fp-2", Tool: "t", Source: "policy:a", Session: "s1"}
	for i := 0; i < 3; i++ {
		if err := s.Mint(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, _ := s.Redeem(ctx, "fp-2", "s1"); !ok {
		t.Fatal("the grant must be redeemable")
	}
	if _, ok, _ := s.Redeem(ctx, "fp-2", "s1"); ok {
		t.Error("one redeem must clear the grant however many times it was minted")
	}
}

// PROVENANCE. A machine grant lives in its own table and names the policy that minted it, so no
// reader can mistake it for a human approval.
func TestGrantProvenanceIsSeparateFromApprovals(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	if err := s.Mint(ctx, proxy.Grant{Fingerprint: "fp-3", Tool: "t", Source: "policy:seq", Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	// it must NOT show up as an approval awaiting or granted by a person
	pend, err := s.ListApprovals(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range pend {
		if a.Fingerprint == "fp-3" {
			t.Fatal("a machine grant must never appear in the human approval queue")
		}
	}
	g, ok, _ := s.Redeem(ctx, "fp-3", "s1")
	if !ok || g.Source == "human" {
		t.Errorf("machine grant provenance: %+v", g)
	}
}

// ATOMICITY, against the real database. A one-shot grant hit by many concurrent Redeems must
// yield exactly ONE success. The DELETE...RETURNING does the finding and the removing in one
// statement precisely so there is no window between them; a check-then-spend pair measured 2
// forwards from a single grant across 32 racing calls.
func TestRedeemIsAtomicUnderConcurrency(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	if err := s.Mint(ctx, proxy.Grant{Fingerprint: "race", Tool: "t", Source: "p", Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := s.Redeem(ctx, "race", "s1"); err == nil && ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("one grant must be redeemable exactly once, got %d of %d", won, n)
	}
}

// SESSION SCOPE, against the real database. Another session's redeem must neither succeed nor
// consume the owner's grant.
func TestRedeemIsSessionScoped(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	if err := s.Mint(ctx, proxy.Grant{Fingerprint: "fp", Tool: "t", Source: "p", Session: "owner"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Redeem(ctx, "fp", "intruder"); ok {
		t.Fatal("another session must not redeem this grant")
	}
	if _, ok, _ := s.Redeem(ctx, "fp", "owner"); !ok {
		t.Fatal("the intruder's failed attempt must not have consumed the owner's grant")
	}
}

// SWEEP clears a session's abandoned grants and leaves other sessions alone.
func TestSweepIsScopedToItsSession(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	for _, g := range []proxy.Grant{
		{Fingerprint: "a1", Tool: "t", Source: "p", Session: "doomed"},
		{Fingerprint: "a2", Tool: "t", Source: "p", Session: "doomed"},
		{Fingerprint: "b1", Tool: "t", Source: "p", Session: "other"},
	} {
		if err := s.Mint(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sweep(ctx, "doomed"); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"a1", "a2"} {
		if _, ok, _ := s.Redeem(ctx, fp, "doomed"); ok {
			t.Errorf("%s must have been swept", fp)
		}
	}
	if _, ok, _ := s.Redeem(ctx, "b1", "other"); !ok {
		t.Error("sweep must not touch another session's grants")
	}
}

// A RESTORED grant is redeemable again: the call it covered did not happen, so the
// authorization is still owed.
func TestRestoreReturnsAnUnusedGrant(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	g := proxy.Grant{Fingerprint: "r1", Tool: "t", Source: "p", Session: "s1"}
	if err := s.Mint(ctx, g); err != nil {
		t.Fatal(err)
	}
	claimed, ok, _ := s.Redeem(ctx, "r1", "s1")
	if !ok {
		t.Fatal("claim failed")
	}
	if err := s.Restore(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Redeem(ctx, "r1", "s1"); !ok {
		t.Error("a restored grant must be redeemable again")
	}
}
