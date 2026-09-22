package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/health"
)

func get(t *testing.T, h http.HandlerFunc) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v: %s", err, rec.Body.String())
	}
	return rec.Code, body
}

func ok(context.Context) error { return nil }

func TestLiveIsAlways200(t *testing.T) {
	code, body := get(t, health.Live(nil))
	if code != 200 || body["ok"] != true {
		t.Fatalf("Live(nil): %d %v", code, body)
	}
	if _, has := body["ready"]; has {
		t.Fatal("no ready func => no ready field")
	}
	// Liveness stays 200 even when readiness says no. That is the whole point of the split.
	code, body = get(t, health.Live(func() bool { return false }))
	if code != 200 || body["ready"] != false {
		t.Fatalf("Live(not ready): %d %v, want 200 with ready:false", code, body)
	}
}

func TestReadyAllPass(t *testing.T) {
	code, body := get(t, health.Ready(time.Second,
		health.Check{Name: "a", Fn: ok}, health.Check{Name: "b", Fn: ok}))
	if code != 200 || body["ready"] != true {
		t.Fatalf("%d %v", code, body)
	}
	checks := body["checks"].(map[string]any)
	if checks["a"] != "ok" || checks["b"] != "ok" {
		t.Fatalf("checks: %v", checks)
	}
}

func TestReadyOneFailureIs503AndNamesIt(t *testing.T) {
	code, body := get(t, health.Ready(time.Second,
		health.Check{Name: "store", Fn: ok},
		health.Check{Name: "fleet", Fn: func(context.Context) error { return errors.New("no downstream connected") }}))
	if code != http.StatusServiceUnavailable || body["ready"] != false {
		t.Fatalf("%d %v", code, body)
	}
	checks := body["checks"].(map[string]any)
	if checks["store"] != "ok" || checks["fleet"] != "no downstream connected" {
		t.Fatalf("operator must see which check failed and why: %v", checks)
	}
}

// A check that ignores its context must not hang the probe; k8s would otherwise mark the pod
// unhealthy for the wrong reason (probe timeout) and hide the real one.
func TestReadyBoundsAnUncooperativeCheck(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	code, body := get(t, health.Ready(50*time.Millisecond,
		health.Check{Name: "stuck", Fn: func(context.Context) error { <-release; return nil }}))
	if took := time.Since(start); took > time.Second {
		t.Fatalf("probe took %s; must return at the timeout, not when the check does", took)
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, want 503", code)
	}
	if got := body["checks"].(map[string]any)["stuck"]; got != "timeout after 50ms" {
		t.Fatalf("stuck check reported %q", got)
	}
}

func TestReadyNoChecksIs200(t *testing.T) {
	if code, _ := get(t, health.Ready(time.Second)); code != 200 {
		t.Fatalf("no dependencies => ready; got %d", code)
	}
}

func TestHTTPOK(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer up.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	ctx := context.Background()
	if err := health.HTTPOK(up.URL)(ctx); err != nil {
		t.Fatalf("2xx must pass: %v", err)
	}
	if err := health.HTTPOK(down.URL)(ctx); err == nil {
		t.Fatal("503 must fail")
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	if err := health.HTTPOK(gone.URL)(ctx); err == nil {
		t.Fatal("unreachable must fail")
	}
}

func TestDir(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := health.Dir(d)(ctx); err != nil {
		t.Fatalf("dir: %v", err)
	}
	if err := health.Dir(f)(ctx); err == nil {
		t.Fatal("a file is not a directory")
	}
	if err := health.Dir(filepath.Join(d, "missing"))(ctx); err == nil {
		t.Fatal("missing path must fail")
	}
}
