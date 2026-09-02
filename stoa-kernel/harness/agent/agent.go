// Package agent is the orchestrator's tool-use loop: a model proposes tool calls, each is
// routed THROUGH stag-proxy (which gates it), and results feed back. The model is the
// untrusted proposer; stag decides what is allowed. Model-agnostic via ToolModel
// (Claude and OpenAI/OpenRouter both implement it).
package agent

// file-kw: agent loop tool-use propose gate verdict forward transcript sse max-turns untrusted-proposer connect transport http stdio daemon-endpoint bound-session-url

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool is a gated tool surfaced by stag-proxy (the model may propose calls to it).
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ToolCall is a model-proposed call.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult is fed back to the model after a call is gated (and maybe executed).
type ToolResult struct {
	CallID  string
	Content string
	IsError bool // a gate refusal or a downstream error
}

// Turn is one model response. No Calls => final (Text is the answer).
type Turn struct {
	Text  string
	Calls []ToolCall
}

// ToolModel does tool-use and keeps its own conversation state: Propose runs the next
// turn given the previous turn's tool results (nil on the first call).
type ToolModel interface {
	Propose(ctx context.Context, results []ToolResult) (Turn, error)
	Name() string
}

// Event is a transcript event streamed to the caller during a run.
type Event struct {
	Kind    string `json:"kind"` // text | propose | verdict | done | error
	Text    string `json:"text,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Args    string `json:"args,omitempty"`
	Allowed bool   `json:"allowed"`
	Result  string `json:"result,omitempty"`
}

// Run drives the model<->gate loop. emit streams transcript events. maxTurns bounds it. appr (may
// be nil) enables the live human-approval loop: an escalated call is held, awaited, and replayed
// with the signed token.
func Run(ctx context.Context, model ToolModel, sess *mcp.ClientSession, maxTurns int, appr *ApprovalConfig, emit func(Event)) {
	var results []ToolResult
	for turn := 0; turn < maxTurns; turn++ {
		t, err := model.Propose(ctx, results)
		if err != nil {
			emit(Event{Kind: "error", Text: err.Error()})
			return
		}
		if strings.TrimSpace(t.Text) != "" {
			emit(Event{Kind: "text", Text: t.Text})
		}
		if len(t.Calls) == 0 {
			emit(Event{Kind: "done"})
			return
		}
		results = nil
		for _, c := range t.Calls {
			emit(Event{Kind: "propose", Tool: c.Name, Args: compact(c.Input)})
			out, isErr := callGated(ctx, sess, c, appr, emit)
			emit(Event{Kind: "verdict", Tool: c.Name, Allowed: !isErr, Result: out})
			results = append(results, ToolResult{CallID: c.ID, Content: out, IsError: isErr})
		}
	}
	emit(Event{Kind: "done", Text: fmt.Sprintf("stopped after %d turns", maxTurns)})
}

// callGated routes one proposed call through the MCP session (stag-proxy). A gate denial comes back
// as IsError; the call never reached the real downstream tool. When the gate ESCALATES an
// approval-gated call and appr is set, the call is held: await a human decision, then replay it
// VERBATIM (plus the signed token) on approval — the model does not re-decide.
func callGated(ctx context.Context, sess *mcp.ClientSession, c ToolCall, appr *ApprovalConfig, emit func(Event)) (string, bool) {
	var args map[string]any
	_ = json.Unmarshal(c.Input, &args)
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: c.Name, Arguments: args})
	if err != nil {
		return fmt.Sprintf("transport error: %v", err), true
	}

	if appr != nil {
		if id, ok := escalationID(res); ok {
			emit(Event{Kind: "await", Tool: c.Name, Result: "escalated — awaiting human approval (" + id + ")"})
			token, status, werr := appr.await(ctx, id)
			if werr != nil {
				return "approval wait error: " + werr.Error(), true
			}
			if status != "approved" {
				emit(Event{Kind: "await", Tool: c.Name, Allowed: false, Result: "approval " + status})
				return fmt.Sprintf("action not performed — approval %s", status), true
			}
			emit(Event{Kind: "retry", Tool: c.Name, Allowed: true, Result: "approved — replaying with signed release"})
			retry := make(map[string]any, len(args)+1)
			for k, v := range args {
				retry[k] = v
			}
			retry["approval_token"] = token
			res2, err2 := sess.CallTool(ctx, &mcp.CallToolParams{Name: c.Name, Arguments: retry})
			if err2 != nil {
				return "retry transport error: " + err2.Error(), true
			}
			return textOf(res2), res2.IsError
		}
	}
	return textOf(res), res.IsError
}

// textOf concatenates the text content blocks of a tool result.
func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, ct := range res.Content {
		if tc, ok := ct.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Connect dials stag-proxy (a shell command) as an MCP client over STDIO and returns a live
// session plus the gated tools it presents. The caller must Close the session.
func Connect(ctx context.Context, proxyCmd string) (*mcp.ClientSession, []Tool, error) {
	fields := strings.Fields(proxyCmd)
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("empty stag-proxy command")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "event-harness", Version: "0.1"}, nil)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(fields[0], fields[1:]...)}, nil)
	if err != nil {
		return nil, nil, err
	}
	tools, err := listTools(ctx, sess)
	if err != nil {
		return nil, nil, err
	}
	return sess, tools, nil
}

// kw: connect transport auto http-vs-stdio endpoint-or-command daemon spawn
// ConnectAuto dials stag-proxy by whichever transport the target names: an http(s) URL is a standing
// DAEMON endpoint (the /mcp/<token> a dispatcher bound), anything else is a stdio command to spawn.
//
// The distinction is not cosmetic. Handing a bound session URL to the stdio path makes the harness
// fork/exec the URL as a program — it fails with "no such file or directory", which reads as a missing
// binary rather than the transport mismatch it is. One entry point, so a caller cannot pick wrong.
func ConnectAuto(ctx context.Context, target string) (*mcp.ClientSession, []Tool, error) {
	if isHTTPEndpoint(target) {
		return ConnectHTTP(ctx, target)
	}
	return Connect(ctx, target)
}

// kw: http endpoint detect url scheme transport-choice
// isHTTPEndpoint reports whether target names a daemon endpoint rather than a command to spawn.
func isHTTPEndpoint(target string) bool {
	t := strings.TrimSpace(target)
	return strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")
}

// ConnectHTTP dials a standing stag-proxy DAEMON over streamable HTTP (session→recipe, Planning/24
// v2). endpoint is the /mcp/<token> URL the dispatcher bound; the session sees only the tools that
// token's recipe governs. The caller must Close the session.
func ConnectHTTP(ctx context.Context, endpoint string) (*mcp.ClientSession, []Tool, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "event-harness", Version: "0.1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		return nil, nil, err
	}
	tools, err := listTools(ctx, sess)
	if err != nil {
		return nil, nil, err
	}
	return sess, tools, nil
}

// listTools reads the session's tools/list into the agent's Tool shape; closes the session on error.
func listTools(ctx context.Context, sess *mcp.ClientSession) ([]Tool, error) {
	lt, err := sess.ListTools(ctx, nil)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	tools := make([]Tool, 0, len(lt.Tools))
	for _, t := range lt.Tools {
		schema, _ := json.Marshal(t.InputSchema)
		tools = append(tools, Tool{Name: t.Name, Description: t.Description, Schema: schema})
	}
	return tools, nil
}

func compact(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(m)
	return string(b)
}
