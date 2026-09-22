package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// awaitGate returns once every dependency answers /ready, tolerating one that comes up late.
func TestAwaitGateReturnsWhenAllReady(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			t.Errorf("probed %s, want /ready", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer up.Close()

	var calls atomic.Int32
	late := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // not ready yet
			return
		}
		w.WriteHeader(200)
	}))
	defer late.Close()

	done := make(chan struct{})
	go func() {
		awaitGate(context.Background(), 5*time.Millisecond, []dep{{"a", up.URL}, {"b", late.URL}, {"skipped", ""}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("awaitGate never returned after both dependencies became ready")
	}
	if calls.Load() < 3 {
		t.Fatalf("late dependency was probed %d times; it should have been retried until ready", calls.Load())
	}
}

// A dependency that never comes up must not pin the goroutine past shutdown.
func TestAwaitGateStopsOnContextCancel(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		awaitGate(ctx, 5*time.Millisecond, []dep{{"never", down.URL}})
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitGate ignored ctx cancellation")
	}
}

// Nothing configured, nothing to wait for: returns immediately, no probe, no log spam.
func TestAwaitGateNoDepsReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		awaitGate(context.Background(), time.Hour, []dep{{"a", ""}, {"b", ""}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("awaitGate with no configured deps must return at once")
	}
}
