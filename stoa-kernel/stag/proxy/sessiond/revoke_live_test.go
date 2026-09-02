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

// liveDaemon is a daemon with a real downstream, so a cleared call actually reaches a tool. The
// revocation tests need a session that genuinely WORKS before it is revoked — otherwise "refused
// after revoke" proves nothing.
func liveDaemon(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	down := mcp.NewServer(&mcp.Implementation{Name: "mock-k8s", Version: "0"}, nil)
	down.AddTool(&mcp.Tool{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "scaled by downstream"}}}, nil
		})
	dst, dct := mcp.NewInMemoryTransports()
	if _, err := down.Connect(ctx, dst, nil); err != nil {
		t.Fatalf("downstream connect: %v", err)
	}
	downSession, err := mcp.NewClient(&mcp.Implementation{Name: "daemon", Version: "0"}, nil).Connect(ctx, dct, nil)
	if err != nil {
		t.Fatalf("downstream client: %v", err)
	}
	t.Cleanup(func() { downSession.Close() })

	ts := httptest.NewServer(sessiond.Handler(sessiond.NewRegistry(), sessiond.Deps{
		Fleet: mcpgate.NewFleet([]mcpgate.Downstream{{
			Name: "downstream", Session: downSession,
			Tools: []*mcp.Tool{{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}},
		}}),
		LoadRecipe: recipeLoader(),
		Auth:       &auth.Authenticator{Tokens: testTokens},
	}))
	t.Cleanup(ts.Close)
	return ts
}

// REGRESSION. Revoking must reach the agent ALREADY CONNECTED, not merely lock the door behind it.
//
// The MCP SDK resolves a session once per transport and reuses the server it built, so a revocation
// check that lives only in getServer never runs again: a client that keeps its Mcp-Session-Id sails
// straight through. This was a real hole — revoke reported success while the connected agent kept
// calling tools, which is the worst possible shape for a control an operator reaches for during an
// incident. A test that reconnects between calls CANNOT catch it; this one holds one session.
func TestRevokeEvictsAnAlreadyConnectedAgent(t *testing.T) {
	ts := liveDaemon(t)
	ctx := context.Background()

	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")
	sess, err := connectMCP(ctx, ts.URL, tok) // ONE session, held across the revoke
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "downstream__scale_deployment", Arguments: map[string]any{"namespace": "dev"}})
	if err != nil || res.IsError {
		t.Fatalf("the session must work BEFORE revocation: err=%v isError=%v", err, res != nil && res.IsError)
	}

	if code := deleteSession(t, ts.URL, testTokens.Dispatch, tok); code != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200", code)
	}

	// the SAME transport, already established — this is the case the old check missed.
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "downstream__scale_deployment", Arguments: map[string]any{"namespace": "dev"}})
	served := err == nil && res != nil && !res.IsError
	if served {
		t.Fatal("SECURITY: a revoked session kept serving an already-connected agent — revocation must evict, not merely lock the door")
	}
}

// A revoked session must not keep answering tools/list either: its authority is gone, not merely its
// ability to act.
func TestRevokedSessionStopsListingTools(t *testing.T) {
	ts := liveDaemon(t)
	ctx := context.Background()

	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")
	sess, err := connectMCP(ctx, ts.URL, tok)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()
	if _, err := sess.ListTools(ctx, nil); err != nil {
		t.Fatalf("tools/list must work before revocation: %v", err)
	}

	deleteSession(t, ts.URL, testTokens.Dispatch, tok)

	if _, err := sess.ListTools(ctx, nil); err == nil {
		t.Error("a revoked session still listed its tools")
	}
}
