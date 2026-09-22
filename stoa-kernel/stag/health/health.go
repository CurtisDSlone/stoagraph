// Package health is the liveness/readiness split every binary in this product answers.
//
// Two questions, two endpoints, because k8s reacts to them differently:
//
//	GET /health  liveness   "is the process alive?"  Always 200 while the process runs. A failing
//	                        liveness probe RESTARTS the pod, so a dependency outage must never fail it:
//	                        restarting stag-serve does not bring Postgres back.
//	GET /ready   readiness  "can it serve right now?" 200 when every dependency check passes, 503
//	                        otherwise. A failing readiness probe pulls the pod out of the Service so
//	                        traffic stops arriving, and puts it back when the checks pass again.
//
// Checks are plain functions so this package imports nothing from the store, the fleet, or the
// orchestrator; each binary hands in the checks it actually depends on.
package health

// file-kw: health liveness readiness probe k8s 503 dependency-check fail-closed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Check is one readiness dependency: a name for the probe body and a function that returns nil when
// the dependency is reachable. Fn MUST honor ctx; a check that ignores it is still bounded by Ready's
// timeout, but its goroutine lingers until it returns.
type Check struct {
	Name string
	Fn   func(context.Context) error
}

// Live is the liveness handler: 200 {"ok":true} unconditionally. When ready is non-nil its result is
// added as "ready" so a human (or compose, which only checks the status) can see both at a glance.
func Live(ready func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"ok": true}
		if ready != nil {
			body["ready"] = ready()
		}
		write(w, http.StatusOK, body)
	}
}

// Ready is the readiness handler. Every check runs concurrently under one deadline; the response is
// 200 when all pass, 503 when any fails or times out, and the body names each check's outcome so an
// operator reading a failing probe knows WHICH dependency is down, not just that one is.
func Ready(timeout time.Duration, checks ...Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		type result struct {
			name string
			err  error
		}
		results := make(chan result, len(checks))
		for _, c := range checks {
			go func(c Check) {
				done := make(chan error, 1)
				go func() { done <- c.Fn(ctx) }()
				select {
				case err := <-done:
					results <- result{c.Name, err}
				case <-ctx.Done():
					results <- result{c.Name, fmt.Errorf("timeout after %s", timeout)}
				}
			}(c)
		}

		out := make(map[string]string, len(checks))
		ready := true
		for range checks {
			res := <-results
			if res.err != nil {
				ready = false
				out[res.name] = res.err.Error()
			} else {
				out[res.name] = "ok"
			}
		}
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		write(w, status, map[string]any{"ready": ready, "checks": out})
	}
}

// HTTPOK is a check that GETs url and passes on any 2xx. Use it to make one service's readiness depend
// on another's: harness-serve is not ready until the gate it dispatches through is.
func HTTPOK(url string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		}
		return nil
	}
}

// Dir is a check that path exists and is a directory. For state a binary reads from disk (the recipe
// store, a tool workspace): a mount that did not attach shows up here, not on the first request.
func Dir(path string) func(context.Context) error {
	return func(context.Context) error {
		fi, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", path)
		}
		return nil
	}
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
