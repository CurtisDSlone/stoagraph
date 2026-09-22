package graceful_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/graceful"
)

// freePort reserves a port by listening and closing, so the server under test can bind it.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitUp(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := http.Get(url); err == nil {
			_ = r.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never came up", url)
}

func TestGraceDefaultAndEnv(t *testing.T) {
	t.Setenv("STAG_SHUTDOWN_GRACE", "")
	if got := graceful.Grace(); got != graceful.DefaultGrace {
		t.Fatalf("unset: %s, want %s", got, graceful.DefaultGrace)
	}
	t.Setenv("STAG_SHUTDOWN_GRACE", "3s")
	if got := graceful.Grace(); got != 3*time.Second {
		t.Fatalf("3s: got %s", got)
	}
	for _, bad := range []string{"nope", "-1s", "0"} {
		t.Setenv("STAG_SHUTDOWN_GRACE", bad)
		if got := graceful.Grace(); got != graceful.DefaultGrace {
			t.Fatalf("%q must fall back to default, got %s", bad, got)
		}
	}
}

// The contract that matters for k8s: a request already in flight when the shutdown signal arrives
// completes and gets its response; the server then exits cleanly within the grace window.
func TestServeDrainsInFlightRequest(t *testing.T) {
	addr := freePort(t)
	started := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, "finished")
	})
	srv := &http.Server{Addr: addr, Handler: mux}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- graceful.Serve(ctx, srv, 5*time.Second) }()
	waitUp(t, "http://"+addr+"/health")

	// Start a request that will be mid-flight when shutdown begins.
	body := make(chan string, 1)
	go func() {
		r, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			body <- "ERR: " + err.Error()
			return
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		body <- string(b)
	}()
	<-started

	cancel() // the "SIGTERM"
	// New connections must be refused while the old one drains.
	time.Sleep(50 * time.Millisecond)
	if _, err := (&http.Client{Timeout: 200 * time.Millisecond}).Get("http://" + addr + "/health"); err == nil {
		t.Fatal("server accepted a new connection after shutdown began")
	}

	close(release)
	if got := <-body; got != "finished" {
		t.Fatalf("in-flight request did not complete cleanly: %q", got)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil on clean drain", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after drain")
	}
}

func TestServeReturnsErrorWhenDrainExceedsGrace(t *testing.T) {
	addr := freePort(t)
	started := make(chan struct{})
	hold := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stuck", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-hold
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- graceful.Serve(ctx, srv, 100*time.Millisecond) }()
	go func() { _, _ = http.Get("http://" + addr + "/stuck") }()
	<-started
	cancel()
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("a request that outlives the grace window must surface as a shutdown error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve hung past its grace window")
	}
	close(hold)
}

func TestServeReturnsListenErrorImmediately(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srv := &http.Server{Addr: l.Addr().String(), Handler: http.NewServeMux()}
	err = graceful.Serve(context.Background(), srv, time.Second)
	if err == nil {
		t.Fatal("binding an occupied port must fail, not block")
	}
}

func TestWaitDrainsOrTimesOut(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { time.Sleep(20 * time.Millisecond); wg.Done() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !graceful.Wait(ctx, &wg) {
		t.Fatal("group finished within the window but Wait reported timeout")
	}

	var stuck sync.WaitGroup
	stuck.Add(1)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	if graceful.Wait(ctx2, &stuck) {
		t.Fatal("group never finished but Wait reported drained")
	}
	stuck.Done()
}
