package mcpgate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
)

// authedMCP stands up a minimal MCP server (one tool) behind a header check — a stand-in for an
// authenticated downstream. Any request missing the exact header/value gets 401.
func authedMCP(t *testing.T, header, value string) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "authed", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "ping", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil
		})
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(header) != value {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		streamable.ServeHTTP(w, r)
	}))
}

func TestConnectDownstreamAuth(t *testing.T) {
	const token = "sekret-123"
	ctx := context.Background()

	// --- bearer scheme ---
	bs := authedMCP(t, "Authorization", "Bearer "+token)
	defer bs.Close()

	// correct credential -> the gate authenticates -> connects + lists the tool
	sess, tools, _, err := mcpgate.Connect(ctx, "http", bs.URL, mcpgate.Auth{Scheme: "bearer", Credential: token})
	if err != nil {
		t.Fatalf("bearer connect with the right token should succeed: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "ping" {
		t.Fatalf("want the ping tool, got %+v", tools)
	}
	_ = sess.Close()

	// no auth against a protected server -> 401 -> fail closed
	if _, _, _, err := mcpgate.Connect(ctx, "http", bs.URL, mcpgate.Auth{}); err == nil {
		t.Error("unauthenticated connect must fail against a protected server")
	}
	// wrong credential -> 401 -> fail closed
	if _, _, _, err := mcpgate.Connect(ctx, "http", bs.URL, mcpgate.Auth{Scheme: "bearer", Credential: "wrong"}); err == nil {
		t.Error("a wrong credential must fail")
	}
	// bearer configured but credential empty -> fail closed BEFORE any connect (no silent unauth)
	if _, _, _, err := mcpgate.Connect(ctx, "http", bs.URL, mcpgate.Auth{Scheme: "bearer"}); err == nil {
		t.Error("bearer with an empty credential must fail closed")
	}

	// --- custom header scheme ---
	hs := authedMCP(t, "X-API-Key", token)
	defer hs.Close()
	sess2, _, _, err := mcpgate.Connect(ctx, "http", hs.URL, mcpgate.Auth{Scheme: "header", Header: "X-API-Key", Credential: token})
	if err != nil {
		t.Fatalf("header-scheme connect should succeed: %v", err)
	}
	_ = sess2.Close()

	// oauth is not supported in v1 -> explicit error, not a silent unauthenticated connect
	if _, _, _, err := mcpgate.Connect(ctx, "http", hs.URL, mcpgate.Auth{Scheme: "oauth"}); err == nil {
		t.Error("oauth scheme must error (v1.1)")
	}
}
