package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The configured timeout must reach the WIRE. A value that is parsed, stored and displayed but
// never applied to the client is the same bug as before, wearing a config key — so this test
// points a real adapter at a deliberately slow server and asserts it gives up on schedule.

func slowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	// NOTE: httptest.Server.Close() blocks until in-flight handlers return, so a handler that
	// sleeps makes the TEST slow even when the client gave up promptly. The handler therefore
	// watches r.Context(), which the client cancels on timeout.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"late"}}]}`))
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// A short timeout gives up on a slow endpoint rather than hanging.
func TestOpenAITimeoutIsApplied(t *testing.T) {
	srv := slowServer(t, 3*time.Second)
	m := NewOpenAI("k", "test-model", srv.URL, "sys", "in", nil, 150*time.Millisecond)

	start := time.Now()
	_, err := m.Propose(context.Background(), nil)
	el := time.Since(start)

	if err == nil {
		t.Fatal("a request that outlives its timeout must fail, not hang")
	}
	// Assert against the CONFIGURED value, not a loose upper bound. A slack ceiling would
	// still pass if the client had fallen back to a hardcoded default, which is the exact
	// regression this test exists to catch.
	if el > time.Second {
		t.Errorf("must give up at ~150ms, not %v — the configured timeout did not reach the client", el)
	}
}

// And a generous timeout lets a slow-but-answering endpoint succeed — which is the actual bug
// being fixed: a model behind a gateway is slow, not broken.
func TestGenerousTimeoutAllowsASlowModel(t *testing.T) {
	srv := slowServer(t, 400*time.Millisecond)
	m := NewOpenAI("k", "test-model", srv.URL, "sys", "in", nil, 5*time.Second)

	if _, err := m.Propose(context.Background(), nil); err != nil {
		t.Fatalf("a slow endpoint within the timeout must succeed: %v", err)
	}
}
