package mcpgate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

const policySrc = `recipe: write_note_policy
version: 1
rules:
  note.allowed:
    kind: set_membership
    set: ["hello", "status-ok", "deploy-done"]
steps:
  - id: propose_text
    kind: propose
    out: text
  - id: apply
    kind: sink
    in: text
    field: mcp.write_note.text
    sensitivity: authoritative
    rule: note.allowed
    actor: "policy:mcp_proxy"
`

// a minimal JSON Schema; the low-level ToolHandler does not validate against it,
// but AddTool requires every tool to carry an input schema.
var noteSchema any = json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}}}`)

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

// TestGatingProxyEndToEnd drives the whole loop over real MCP transports:
// agent -> [stag gating server] -> [stag client] -> downstream server.
// The load-bearing assertion: a DENIED call never reaches the downstream server.
func TestGatingProxyEndToEnd(t *testing.T) {
	ctx := context.Background()

	// --- the "real" downstream server: write_note echoes and records what it saw
	var received []string
	downstreamSrv := mcp.NewServer(&mcp.Implementation{Name: "downstream", Version: "0"}, nil)
	downstreamSrv.AddTool(&mcp.Tool{Name: "write_note", Description: "write a note", InputSchema: noteSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var m map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &m)
			text := fmt.Sprint(m["text"])
			received = append(received, text)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "noted: " + text}}}, nil
		})

	// pair A: stag's client <-> the downstream server
	dClientT, dServerT := mcp.NewInMemoryTransports()
	dServerSess, err := downstreamSrv.Connect(ctx, dServerT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dServerSess.Close()
	proxyClient := mcp.NewClient(&mcp.Implementation{Name: "stag-client", Version: "0"}, nil)
	downstream, err := proxyClient.Connect(ctx, dClientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer downstream.Close()

	// the deterministic gate
	p, err := recipe.Parse([]byte(policySrc))
	if err != nil {
		t.Fatal(err)
	}
	gate := proxy.Gate{Routes: proxy.Router{
		proxy.AdvertisedName("downstream", "write_note"): {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "downstream", Tool: "write_note"},
	}}

	// stag's gating MCP server, and pair B: the agent <-> that server
	gatingSrv := mcpgate.NewGatingServer(gate,
		mcpgate.NewFleet([]mcpgate.Downstream{{Name: "downstream", Session: downstream,
			Tools: []*mcp.Tool{{Name: "write_note", Description: "gated write", InputSchema: noteSchema}}}}),
		mcpgate.ReadChannel{})
	aClientT, aServerT := mcp.NewInMemoryTransports()
	gatingSess, err := gatingSrv.Connect(ctx, aServerT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gatingSess.Close()
	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil)
	agentSess, err := agent.Connect(ctx, aClientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer agentSess.Close()

	// --- ALLOWED call: cleared, forwarded, downstream ran it
	res, err := agentSess.CallTool(ctx, &mcp.CallToolParams{Name: "downstream__write_note", Arguments: map[string]any{"text": "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("allowed call must not be an error: %s", textOf(t, res))
	}
	if got := textOf(t, res); got != "noted: hello" {
		t.Errorf("downstream result should be forwarded back: %q", got)
	}
	if len(received) != 1 || received[0] != "hello" {
		t.Fatalf("downstream should have received the allowed call: %v", received)
	}

	// --- DENIED call: blocked; downstream must NEVER see it
	res2, err := agentSess.CallTool(ctx, &mcp.CallToolParams{Name: "downstream__write_note", Arguments: map[string]any{"text": "rm -rf /"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.IsError {
		t.Errorf("denied call must return a tool error, got: %q", textOf(t, res2))
	}
	if !strings.Contains(textOf(t, res2), "stag gate") {
		t.Errorf("denied result should name the gate: %q", textOf(t, res2))
	}
	// THE LOAD-BEARING ASSERTION: the denied value never reached downstream.
	if len(received) != 1 {
		t.Fatalf("COMPLETE-MEDIATION BREACH: downstream saw a denied call: %v", received)
	}
}
