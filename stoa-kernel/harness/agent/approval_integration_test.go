package agent_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/agent"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A full, deterministic exercise of the live approval loop — no model, no cluster:
//
//	fake gating MCP server: escalate (with approvalId in _meta) until an approval_token is present,
//	  then succeed;
//	httptest stag-serve: pending until "approved", handing back the token;
//	an auto-approver flips the row after a beat.
//
// CallGated must hold the escalated call, await approval, replay it VERBATIM + token, and return the
// downstream success — never re-proposing.
func TestCallGatedApprovalLoop(t *testing.T) {
	const approvalID = "appr-xyz"
	const token = "SIGNED-RELEASE"

	// --- fake gating MCP server (stands in for stag-proxy) ---
	var firstArgs, retryArgs atomic.Value
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-proxy", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		if tok, ok := args["approval_token"]; ok && tok == token {
			retryArgs.Store(args)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "scaled web to 4 in prod"}}}, nil
		}
		firstArgs.Store(args)
		// escalate: refuse + surface the approval id in _meta (as mcpgate does)
		return &mcp.CallToolResult{
			Meta:    mcp.Meta{"stag": map[string]any{"verdict": "escalate", "approvalId": approvalID}},
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: `stag gate: escalate — "scale_deployment" not forwarded`}},
		}, nil
	})

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	// --- httptest stag-serve: pending, then approved+token after the auto-approver flips it ---
	var approved atomic.Bool
	serve := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if approved.Load() {
			_, _ = w.Write([]byte(`{"status":"approved","token":"` + token + `"}`))
		} else {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		}
	}))
	defer serve.Close()
	go func() { time.Sleep(30 * time.Millisecond); approved.Store(true) }() // "a human approves"

	appr := &agent.ApprovalConfig{BaseURL: serve.URL, Poll: 5 * time.Millisecond, Timeout: 3 * time.Second, HTTP: serve.Client()}

	// --- drive the real CallGated with the held call ---
	var events []agent.Event
	call := agent.ToolCall{ID: "c1", Name: "scale_deployment", Input: json.RawMessage(`{"namespace":"prod","replicas":"4","deployment":"web"}`)}
	out, isErr, _ := agent.CallGated(ctx, sess, call, appr, func(e agent.Event) { events = append(events, e) })

	if isErr {
		t.Fatalf("approved retry must succeed, got error result: %q", out)
	}
	if !strings.Contains(out, "scaled web to 4 in prod") {
		t.Fatalf("want downstream success text, got %q", out)
	}
	// the replay must carry the token AND the original args verbatim.
	ra, _ := retryArgs.Load().(map[string]any)
	if ra["approval_token"] != token || ra["namespace"] != "prod" || ra["replicas"] != "4" || ra["deployment"] != "web" {
		t.Fatalf("retry must replay verbatim args + token, got %v", ra)
	}
	// the first (held) attempt must NOT have carried a token.
	fa, _ := firstArgs.Load().(map[string]any)
	if _, leaked := fa["approval_token"]; leaked {
		t.Error("the initial attempt must not carry a token")
	}
	// the transcript must show the await then the retry.
	var sawAwait, sawRetry bool
	for _, e := range events {
		sawAwait = sawAwait || e.Kind == "await"
		sawRetry = sawRetry || e.Kind == "retry"
	}
	if !sawAwait || !sawRetry {
		t.Errorf("transcript must show await + retry, got %+v", events)
	}
}
