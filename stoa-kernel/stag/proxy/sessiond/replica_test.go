package sessiond_test

// kw-test: bindings are shared across daemon REPLICAS. Two Registries over one Sessions stand in for
// two daemons behind one Service: a token bound on A is served by B; revoking on B disarms an agent
// connected to A; and the crossing budget is one counter no matter which replica takes the call.

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

// twoReplicas stands up two daemons sharing one Sessions and one downstream, with the given budget.
func twoReplicas(t *testing.T, ctx context.Context, budget int) (a, b *httptest.Server) {
	t.Helper()
	down := mcp.NewServer(&mcp.Implementation{Name: "mock-k8s", Version: "0"}, nil)
	down.AddTool(&mcp.Tool{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "scaled by downstream"}}}, nil
		})
	dst, dct := mcp.NewInMemoryTransports()
	if _, err := down.Connect(ctx, dst, nil); err != nil {
		t.Fatal(err)
	}
	downSession, err := mcp.NewClient(&mcp.Implementation{Name: "daemon", Version: "0"}, nil).Connect(ctx, dct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = downSession.Close() })

	deps := func() sessiond.Deps {
		return sessiond.Deps{
			Fleet: mcpgate.NewFleet([]mcpgate.Downstream{{
				Name: "downstream", Session: downSession,
				Tools: []*mcp.Tool{{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}},
			}}),
			LoadRecipe:     recipeLoader(),
			Auth:           &auth.Authenticator{Tokens: testTokens},
			CrossingBudget: budget,
		}
	}
	shared := sessiond.NewMemorySessions()
	a = httptest.NewServer(sessiond.Handler(sessiond.NewRegistryWith(shared), deps()))
	b = httptest.NewServer(sessiond.Handler(sessiond.NewRegistryWith(shared), deps()))
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)
	return a, b
}

func TestBindingBoundOnOneReplicaIsServedByAnother(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t, ctx, 0)

	tok := createSession(t, a.URL, "scale_deployment", "allow_dev", "namespace")

	// B has never seen this token: it must rehydrate the binding from the shared store and serve it
	// under the SAME policy A compiled (allow_dev: dev forwards).
	if out, isErr := callViaSession(t, ctx, b.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
		t.Fatalf("replica B must serve a token bound on A: isErr=%v %q", isErr, out)
	}
	// ...and deny what the policy denies, proving it is the binder's recipe, not a permissive default.
	if out, _ := callViaSession(t, ctx, b.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "prod"}); strings.Contains(out, "scaled by downstream") {
		t.Fatalf("replica B served prod under allow_dev: %q", out)
	}
}

func TestRevokeOnOneReplicaDisarmsAgentOnAnother(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t, ctx, 0)

	tok := createSession(t, a.URL, "scale_deployment", "allow_dev", "namespace")
	// The agent is connected to A and has already made a call, so A holds a compiled, cached binding.
	if out, isErr := callViaSession(t, ctx, a.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
		t.Fatalf("precondition: A serves: %v %q", isErr, out)
	}

	// Revoke through B.
	if code := deleteSession(t, b.URL, testTokens.Dispatch, tok); code != 200 {
		t.Fatalf("revoke via B: %d", code)
	}

	// A's cache is not authority: the next request on A asks the store and is refused.
	if _, err := connectMCP(ctx, a.URL, tok); err == nil {
		t.Fatal("after revoke on B, replica A must refuse the token")
	}
	// And revoking again anywhere reports the miss, not a second success.
	if code := deleteSession(t, a.URL, testTokens.Dispatch, tok); code != 404 {
		t.Fatalf("second revoke must be 404, got %d", code)
	}
}

func TestCrossingBudgetIsSharedAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	a, b := twoReplicas(t, ctx, 2)

	tok := createSession(t, a.URL, "scale_deployment", "allow_dev", "namespace")

	// One crossing on A, one on B: the token's budget of 2 is now spent, regardless of which
	// process took each call.
	if out, isErr := callViaSession(t, ctx, a.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
		t.Fatalf("crossing 1 on A must forward: %v %q", isErr, out)
	}
	if out, isErr := callViaSession(t, ctx, b.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
		t.Fatalf("crossing 2 on B must forward: %v %q", isErr, out)
	}
	// A third, back on A. With per-process counters A would think it had used 1 of 2 and forward.
	out, isErr := callViaSession(t, ctx, a.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"})
	if !isErr || !strings.Contains(out, "stag gate") {
		t.Fatalf("the 3rd crossing must be REFUSED by the shared budget; got isErr=%v %q", isErr, out)
	}
	// A denied call is not a crossing: it must not have consumed the (already spent) budget further,
	// and a deny on B is likewise refused, not forwarded.
	if out, _ := callViaSession(t, ctx, b.URL, tok, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); strings.Contains(out, "scaled by downstream") {
		t.Fatalf("budget spent on both replicas, yet B forwarded: %q", out)
	}
}
