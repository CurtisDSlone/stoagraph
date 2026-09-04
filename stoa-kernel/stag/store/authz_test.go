package store

import (
	"context"
	"path/filepath"
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
	g := proxy.Grant{Fingerprint: "fp-1", Tool: "lab__fix", Source: "policy:lab_repair_badport"}
	if err := s.Mint(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Lookup(ctx, "fp-1")
	if err != nil || !ok {
		t.Fatalf("a minted grant must be found: ok=%v err=%v", ok, err)
	}
	if got.Source != g.Source || got.Tool != g.Tool {
		t.Errorf("grant round-trip: %+v", got)
	}
	if err := s.Burn(ctx, "fp-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Lookup(ctx, "fp-1"); ok {
		t.Error("a burned grant must be gone (replay denied)")
	}
}

// An unminted fingerprint is not a grant, and that is not an error — it is the normal answer
// for every call that was never authorized.
func TestUnknownFingerprintIsNotAGrant(t *testing.T) {
	s := authzStore(t)
	g, ok, err := s.Lookup(context.Background(), "never-minted")
	if err != nil || ok || g.Fingerprint != "" {
		t.Errorf("unknown fingerprint: g=%+v ok=%v err=%v", g, ok, err)
	}
}

// Re-minting REPLACES rather than stacks: a grant is permission for one call, not a counter.
// Two outstanding copies would let a sequence spend one and leave the other live.
func TestReMintDoesNotStack(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	g := proxy.Grant{Fingerprint: "fp-2", Tool: "t", Source: "policy:a"}
	for i := 0; i < 3; i++ {
		if err := s.Mint(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Burn(ctx, "fp-2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Lookup(ctx, "fp-2"); ok {
		t.Error("one burn must clear the grant however many times it was minted")
	}
}

// PROVENANCE. A machine grant lives in its own table and names the policy that minted it, so no
// reader can mistake it for a human approval.
func TestGrantProvenanceIsSeparateFromApprovals(t *testing.T) {
	s := authzStore(t)
	ctx := context.Background()
	if err := s.Mint(ctx, proxy.Grant{Fingerprint: "fp-3", Tool: "t", Source: "policy:seq"}); err != nil {
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
	g, ok, _ := s.Lookup(ctx, "fp-3")
	if !ok || g.Source == "human" {
		t.Errorf("machine grant provenance: %+v", g)
	}
}
