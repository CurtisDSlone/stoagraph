// Package graceful is the one place the four binaries learn to die properly.
//
// Go's default disposition for SIGTERM is immediate exit: no deferred Close runs, listeners drop
// mid-request, an MCP call already forwarded to a downstream is orphaned with no audit line. Under
// k8s that turns terminationGracePeriodSeconds into dead time — the pod is gone on the first signal
// and the grace window buys nothing. This package makes the first signal mean "stop accepting, finish
// what is in flight, then exit", bounded by a grace period, and makes the second signal mean "now".
//
// It is deliberately tiny and imports nothing from the gate or the orchestrator, so both sides may
// use it without touching the architecture boundary.
package graceful

// file-kw: graceful shutdown SIGTERM SIGINT drain grace-period k8s terminationGracePeriodSeconds

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// DefaultGrace is how long a shutdown may spend draining before the process exits regardless. It
// sits under k8s's default 30s terminationGracePeriodSeconds so the drain finishes before SIGKILL.
const DefaultGrace = 20 * time.Second

// Grace returns the drain window: STAG_SHUTDOWN_GRACE as a Go duration ("15s", "1m"), else
// DefaultGrace. A malformed value falls back to the default and says so; it never disables the drain.
func Grace() time.Duration {
	v := os.Getenv("STAG_SHUTDOWN_GRACE")
	if v == "" {
		return DefaultGrace
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("graceful: STAG_SHUTDOWN_GRACE=%q is not a positive duration; using %s", v, DefaultGrace)
		return DefaultGrace
	}
	return d
}

// Context returns a context cancelled on the first SIGINT or SIGTERM. A second signal exits the
// process immediately (status 1) so an operator at a terminal, or a stuck drain, is never trapped
// behind the grace window. The returned cancel releases the signal handler; call it on the way out.
func Context() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-ch:
			log.Printf("graceful: %s — draining (send again to exit now)", sig)
			cancel()
		case <-ctx.Done():
			return
		}
		select {
		case sig := <-ch:
			log.Printf("graceful: second %s — exiting now", sig)
			os.Exit(1)
		case <-time.After(Grace() + 5*time.Second):
			// The drain should have finished and the process exited by now. If we are still here
			// something is wedged past its own deadline; do not hang the pod until SIGKILL.
			log.Printf("graceful: drain exceeded its window; exiting")
			os.Exit(1)
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}

// Serve runs srv until ctx is cancelled, then shuts it down, waiting up to grace for in-flight
// requests to complete. Shutdown stops accepting new connections first, so a readiness probe fails
// closed while existing requests finish. Returns nil on a clean drain, the shutdown error if the
// drain timed out, or the listen error if the server failed before ctx was cancelled.
func Serve(ctx context.Context, srv *http.Server, grace time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		// Failed to bind or crashed before any shutdown was asked for. ErrServerClosed cannot
		// happen here (nobody called Shutdown yet), so this is a real error.
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// ListenAndServe returns ErrServerClosed once Shutdown begins; consume it so the goroutine exits.
	<-errc
	return nil
}

// Wait blocks until wg reaches zero or ctx is done, whichever is first. Reports true when the group
// drained. Use it after Serve returns to wait for background work the HTTP server does not know
// about (harness-serve's governed runs), bounded by the same grace context.
func Wait(ctx context.Context, wg *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
