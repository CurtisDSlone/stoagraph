package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

func TestPingReflectsConnectionState(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("open store must ping: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("closed store must fail ping, or /ready lies")
	}
}
