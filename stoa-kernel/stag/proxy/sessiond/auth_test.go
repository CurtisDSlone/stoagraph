package sessiond_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/sessiond"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// guardedDaemon spins a daemon with the control plane ON and no downstream (no tool call is made —
// these tests are about WHO may bind).
func guardedDaemon(t *testing.T, a *auth.Authenticator) *httptest.Server {
	t.Helper()
	deps := sessiond.Deps{
		// A fleet that OWNS the tool: these tests are about WHO may bind, so the binding itself must
		// succeed for an authorized caller (an unowned tool would be rejected for a different reason).
		Fleet: mcpgate.NewFleet([]mcpgate.Downstream{{
			Name:  "downstream",
			Tools: []*mcp.Tool{{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}},
		}}),
		LoadRecipe: recipeLoader(),
		Auth:       a,
	}
	ts := httptest.NewServer(sessiond.Handler(sessiond.NewRegistry(), deps))
	t.Cleanup(ts.Close)
	return ts
}

// TestBindRequiresDispatchRole is the daemon half of Planning/31. POST /sessions CHOOSES the recipe
// that will govern a session — if anyone can call it, they simply pick the most permissive recipe and
// the "the agent cannot choose its own recipe" invariant collapses.
func TestBindRequiresDispatchRole(t *testing.T) {
	ts := guardedDaemon(t, &auth.Authenticator{Tokens: testTokens})

	// anonymous -> 401
	if code, body := postSession(t, ts.URL, "", "scale_deployment", "allow_dev", "namespace"); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: anonymous bind admitted (got %d): %s", code, body)
	}
	// a wrong secret -> 401
	if code, _ := postSession(t, ts.URL, "not-the-token", "scale_deployment", "allow_dev", "namespace"); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: bogus token admitted (got %d)", code)
	}
	// the HUMAN's approve token is NOT a binder credential -> 401 (least privilege runs both ways)
	if code, _ := postSession(t, ts.URL, testTokens.Approve, "scale_deployment", "allow_dev", "namespace"); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: the approve token bound a session (got %d)", code)
	}
	// the orchestrator's dispatch token -> 200
	if code, body := postSession(t, ts.URL, testTokens.Dispatch, "scale_deployment", "allow_dev", "namespace"); code != http.StatusOK {
		t.Errorf("the dispatch role must be able to bind: got %d %s", code, body)
	}
}

// TestAgentEndpointTakesNoBearer pins the deliberate asymmetry: the UNTRUSTED agent connects to
// /mcp/<token> with NO control-plane credential — the opaque session token IS its credential. Handing
// the agent a bearer would give the untrusted side a control-plane secret, exactly backwards.
func TestAgentEndpointTakesNoBearer(t *testing.T) {
	ts := guardedDaemon(t, &auth.Authenticator{Tokens: testTokens})
	ctx := context.Background()

	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace") // binds with `dispatch`

	// the agent connects with the session token in the PATH and no Authorization header at all
	sess, err := connectMCP(ctx, ts.URL, tok)
	if err != nil {
		t.Fatalf("the agent must reach /mcp/<token> WITHOUT a control-plane bearer: %v", err)
	}
	defer sess.Close()

	// and an unknown session token is still refused (fail closed, unchanged)
	if _, err := connectMCP(ctx, ts.URL, "deadbeefdeadbeef00000000deadbeef"); err == nil {
		t.Error("an unknown session token must still fail closed")
	}
}

// TestDaemonNilAuthFailsClosed — a daemon wired without an Authenticator must refuse binds, not
// silently serve them.
func TestDaemonNilAuthFailsClosed(t *testing.T) {
	ts := guardedDaemon(t, nil)
	if code, _ := postSession(t, ts.URL, testTokens.Dispatch, "scale_deployment", "allow_dev", "namespace"); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: nil Auth fell OPEN on POST /sessions (got %d, want 401)", code)
	}
}
