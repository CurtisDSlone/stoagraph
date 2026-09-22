package store_test

import (
	"context"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

var _ proxy.Sessions = (*store.Store)(nil) // the store IS the daemon's session backend

func sampleBinding(id string, budget int) proxy.Binding {
	return proxy.Binding{
		ID: id,
		Routes: []proxy.BindingRoute{
			{Tool: "scale", Server: "k8s", Recipe: "allow_dev", GateArg: "namespace"},
			{Tool: "restart", Server: "k8s", Recipe: "seq", GateArg: "pod", Sequenced: true},
		},
		Providers: []proxy.BindingProvider{{Name: "kb", Kind: "rag", Config: `{"dir":"x"}`}},
		Recipes:   map[string]string{"allow_dev": "recipe: allow_dev\n", "seq": "recipe: seq\n"},
		Budget:    budget,
	}
}

func TestBindingRoundTripAndRevoke(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	want := sampleBinding("abc123", 5)
	if err := s.PutBinding(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetBinding(ctx, "abc123")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.CreatedAt == "" {
		t.Fatal("created_at must be stamped")
	}
	got.CreatedAt = ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
	if has, _ := s.HasBinding(ctx, "abc123"); !has {
		t.Fatal("HasBinding must see the row")
	}
	if n, _ := s.CountBindings(ctx); n != 1 {
		t.Fatalf("count = %d", n)
	}

	removed, err := s.DeleteBinding(ctx, "abc123")
	if err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v", removed, err)
	}
	if removed, _ := s.DeleteBinding(ctx, "abc123"); removed {
		t.Fatal("second revoke must report no-op, not success")
	}
	if has, _ := s.HasBinding(ctx, "abc123"); has {
		t.Fatal("revoked binding must not be live")
	}
	if _, ok, _ := s.GetBinding(ctx, "abc123"); ok {
		t.Fatal("revoked binding must not load")
	}
	// A revoked session crosses nothing.
	if ok, _ := s.ReserveCrossing(ctx, "abc123"); ok {
		t.Fatal("ReserveCrossing on a missing binding must be false")
	}
}

func TestReserveCrossingIsAtomicAndCapped(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.PutBinding(ctx, sampleBinding("cap5", 5)); err != nil {
		t.Fatal(err)
	}

	// 32 racing reservations against a cap of 5: exactly 5 win. This is the multi-replica property
	// (the racers stand in for requests landing on different daemons) on the SQLite path; the
	// postgres test repeats it on the other backend.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.ReserveCrossing(ctx, "cap5")
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 5 {
		t.Fatalf("cap 5, %d reservations won", wins.Load())
	}

	// Release gives one back; the next reserve wins; the one after does not.
	if err := s.ReleaseCrossing(ctx, "cap5"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ReserveCrossing(ctx, "cap5"); !ok {
		t.Fatal("after a release one crossing must be available")
	}
	if ok, _ := s.ReserveCrossing(ctx, "cap5"); ok {
		t.Fatal("cap must hold after the released slot is retaken")
	}
}

func TestReserveCrossingUnlimitedAlwaysWins(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.PutBinding(ctx, sampleBinding("nolimit", 0)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if ok, err := s.ReserveCrossing(ctx, "nolimit"); !ok || err != nil {
			t.Fatalf("unlimited must always reserve: ok=%v err=%v", ok, err)
		}
	}
	// Release never goes below zero.
	if err := s.PutBinding(ctx, sampleBinding("zero", 3)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseCrossing(ctx, "zero"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if ok, _ := s.ReserveCrossing(ctx, "zero"); !ok {
			t.Fatalf("reserve %d of 3 must win after a no-op release", i+1)
		}
	}
	if ok, _ := s.ReserveCrossing(ctx, "zero"); ok {
		t.Fatal("a release below zero must not mint an extra crossing")
	}
}
