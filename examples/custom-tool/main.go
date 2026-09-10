// Your tool server. Copy this folder, add your tools, put StoaGraph in front of it.
//
// This is a normal MCP server — nothing StoaGraph-specific. You register it with the gate
// (POST /api/mcp-servers), write a recipe that gates one of its arguments, and route the tool to that
// recipe. From then on the agent can only call your tool through the gate, on the values your policy
// allows.
//
// Two transports, same code:
//   go run .                 stdio — an agent host (or a host-run gate) spawns it
//   go run . -http :9100     streamable HTTP — a containerised gate reaches it over the network
//
// THE ONE RULE (learned the hard way — see docs): make each tool a SPECIFIC capability with a
// gate-able argument. Do NOT write a generic `run_command(cmd)` — a recipe cannot meaningfully gate an
// arbitrary shell string, and it hands the model unconstrained reach. `notify(channel, text)` can be
// gated (which channels?); `run_command(cmd)` cannot. Granularity of the tool = granularity of control.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	httpAddr := flag.String("http", "", "serve streamable HTTP on this address (empty = stdio)")
	flag.Parse()
	log.SetOutput(os.Stderr) // in stdio mode, stdout carries the protocol — keep logs off it

	srv := mcp.NewServer(&mcp.Implementation{Name: "custom-tool", Version: "0.1.0"}, nil)

	// ─────────────────────────────────────────────────────────────────────────────────────────────
	// ADD YOUR TOOL HERE. This example — notify(channel, text) — is the shape to copy: a real action
	// with an argument worth gating. The `channel` argument is what a recipe will constrain, so the
	// agent can post to #support but never to #exec, no matter what it's convinced to try.
	// ─────────────────────────────────────────────────────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "notify",
		Description: "Post a message to a channel.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"channel": map[string]any{"type": "string", "description": "the destination channel"},
				"text":    map[string]any{"type": "string", "description": "the message body"},
			},
			"required": []string{"channel", "text"},
		},
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Channel string `json:"channel"`
			Text    string `json:"text"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &a)

		// Your real side effect goes here (call Slack, write a row, hit an API). It runs ONLY on values
		// the gate already cleared — so this handler doesn't need to be defensive about `channel`. That
		// check lives in the recipe, where it's deterministic and audited, not in code you have to trust.
		return text(fmt.Sprintf("posted to %s: %s", a.Channel, a.Text)), nil
	})

	// ── run it ──────────────────────────────────────────────────────────────────────────────────
	ctx := context.Background()
	if *httpAddr == "" {
		log.Printf("custom-tool: MCP over stdio")
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, `{"ok":true}`) })
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	log.Printf("custom-tool: MCP over streamable HTTP on %s/mcp", *httpAddr)
	log.Fatal(http.ListenAndServe(*httpAddr, mux))
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}
