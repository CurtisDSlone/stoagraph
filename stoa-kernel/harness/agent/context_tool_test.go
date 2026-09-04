package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// THE HARNESS NEEDS NO CHANGE. It already lists the session's tools and hands them to the model,
// so a provider advertised as a tool arrives through the path that was always there.
//
// This is the whole reason for advertising providers as tools rather than teaching the loop to
// read resources: the fix reaches every MCP client, not only this project's own harness.

type ctxProv struct{ name string }

func (c ctxProv) Name() string { return c.name }
func (c ctxProv) Provide(_ context.Context, q string) ([]provider.ContextItem, error) {
	return []provider.ContextItem{{Source: "runbook-7", Text: "cordon before you drain (" + q + ")"}}, nil
}

func TestHarnessSeesContextProvidersWithNoChanges(t *testing.T) {
	ctx := context.Background()
	srv := mcpgate.NewGatingServer(
		proxy.Gate{Routes: proxy.Router{}},
		mcpgate.NewFleet(nil),
		mcpgate.ReadChannel{Providers: []provider.ContextProvider{ctxProv{"runbooks"}}},
	)
	sc, ss := mcp.NewInMemoryTransports()
	gs, err := srv.Connect(ctx, ss, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()
	cl := mcp.NewClient(&mcp.Implementation{Name: "event-harness", Version: "0.1"}, nil)
	sess, err := cl.Connect(ctx, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// the harness's OWN discovery path, unmodified
	tools, err := listTools(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	var found *Tool
	for i := range tools {
		if tools[i].Name == mcpgate.ContextToolName("runbooks") {
			found = &tools[i]
		}
	}
	if found == nil {
		t.Fatalf("the harness must see the provider among its tools; got %d", len(tools))
	}
	if !strings.Contains(strings.ToLower(found.Description), "untrusted") {
		t.Error("and the description must warn the model the content is untrusted")
	}
	if len(found.Schema) == 0 {
		t.Error("the model needs a schema to call it")
	}

	// and calling it returns context the model can use
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: found.Name, Arguments: json.RawMessage(`{"q":"drain"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			got.WriteString(tc.Text)
		}
	}
	if !strings.Contains(got.String(), "cordon before you drain") {
		t.Errorf("content did not reach the agent: %q", got.String())
	}
	// TRUST POSITION: it arrives as a TOOL RESULT, which is Input-side by construction — the
	// model can read it, and it can never occupy the instruction slot.
	if !strings.Contains(got.String(), "untrusted context") {
		t.Error("the content itself must carry its untrusted label")
	}
}
