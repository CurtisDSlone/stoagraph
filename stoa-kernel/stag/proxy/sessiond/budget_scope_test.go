package sessiond_test

// kw-test: the crossing budget is scoped to the DISPATCHED TOKEN, not the MCP transport session — an
// untrusted agent must not reset the cap N by reconnecting (Planning/34 §6.2, adversarial finding #1).

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/sessiond"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCrossingBudgetIsTokenScoped(t *testing.T) {
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
	defer downSession.Close()

	deps := sessiond.Deps{
		Fleet: mcpgate.NewFleet([]mcpgate.Downstream{{
			Name: "downstream", Session: downSession,
			Tools: []*mcp.Tool{{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}},
		}}),
		LoadRecipe:     recipeLoader(),
		Auth:           &auth.Authenticator{Tokens: testTokens},
		CrossingBudget: 2, // the per-TOKEN cap N
	}
	ts := httptest.NewServer(sessiond.Handler(sessiond.NewRegistry(), deps))
	defer ts.Close()

	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")

	// Each callViaSession opens a FRESH MCP session (connect → call → close), i.e. an agent reconnect.
	// The first two forwarded crossings draw down the token's shared budget of 2.
	for i := 1; i <= 2; i++ {
		if out, isErr := callViaSession(t, ctx, ts.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
			t.Fatalf("crossing %d must forward: isErr=%v %q", i, isErr, out)
		}
	}
	// The THIRD crossing opens yet another fresh MCP session on the SAME token — the reconnect bypass.
	// With a per-token budget this is still refused; with the old per-MCP-session counter it would reset.
	out, isErr := callViaSession(t, ctx, ts.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"})
	if !isErr || !strings.Contains(out, "stag gate") {
		t.Fatalf("the 3rd crossing on a fresh MCP session (same token) must be REFUSED by the token budget; got isErr=%v %q", isErr, out)
	}
}
