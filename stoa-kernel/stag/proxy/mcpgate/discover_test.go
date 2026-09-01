package mcpgate_test

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
)

// TestDiscover stands up an in-memory MCP server exposing two tools and verifies
// Discover lists them (name + schema) over the transport — the admin discovery path.
func TestDiscover(t *testing.T) {
	ctx := context.Background()

	srv := mcp.NewServer(&mcp.Implementation{Name: "downstream", Version: "0"}, nil)
	h := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	}
	srv.AddTool(&mcp.Tool{Name: "read_file", Description: "read a file", InputSchema: noteSchema}, h)
	srv.AddTool(&mcp.Tool{Name: "write_file", Description: "write a file", InputSchema: noteSchema}, h)

	clientT, serverT := mcp.NewInMemoryTransports()
	sess, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	tools, err := mcpgate.Discover(ctx, clientT)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d: %+v", len(tools), tools)
	}
	byName := map[string]mcpgate.DiscoveredTool{}
	for _, tl := range tools {
		byName[tl.Name] = tl
	}
	rf, ok := byName["read_file"]
	if !ok || rf.Description != "read a file" || rf.InputSchema == "" {
		t.Errorf("read_file not discovered faithfully: %+v", rf)
	}
	if _, ok := byName["write_file"]; !ok {
		t.Errorf("write_file not discovered")
	}
}

// unknown transport kind fails closed
func TestDiscoverToolsBadKind(t *testing.T) {
	if _, err := mcpgate.DiscoverTools(context.Background(), "smtp", "x", mcpgate.Auth{}); err == nil {
		t.Error("unknown transport kind must error")
	}
}
