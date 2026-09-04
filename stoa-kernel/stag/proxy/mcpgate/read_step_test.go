package mcpgate_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A `read` step means the RECIPE fetched the context, not the model. The agent calls one governed
// tool and the context arrives with the result — it never chose the source or wrote the question.

func readStepRig(t *testing.T, allowNode string) (context.Context, *mcp.ClientSession, *[]provider.ReadEvent) {
	t.Helper()
	ctx := context.Background()
	var reads []provider.ReadEvent

	var schema any = json.RawMessage(`{"type":"object","properties":{"topic":{"type":"string"},"node":{"type":"string"}}}`)
	down := mcp.NewServer(&mcp.Implementation{Name: "d", Version: "0"}, nil)
	down.AddTool(&mcp.Tool{Name: "act", Description: "act", InputSchema: schema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ACTION-RESULT"}}}, nil
		})
	dc, ds := mcp.NewInMemoryTransports()
	dss, err := down.Connect(ctx, ds, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dss.Close() })
	pc := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	downstream, err := pc.Connect(ctx, dc, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { downstream.Close() })

	topic := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"drain"}}
	node := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{allowNode}}
	rec := stag.Recipe{Steps: []stag.Step{
		{Id: "p_t", Kind: stag.NodePropose, Out: "topic"},
		{Id: "p_n", Kind: stag.NodePropose, Out: "node"},
		{Id: "brief", Kind: stag.NodeRead, Provider: "runbooks",
			QuerySlot: "topic", QueryRule: &topic, QueryRuleID: "topic.allowed"},
		{Id: "act", Kind: stag.NodeSink, In: "node", Field: "act", Sensitivity: stag.SinkAuthoritative,
			Rule: &node, RuleID: "node.ok", Actor: "a"},
	}}
	gate := proxy.Gate{Routes: proxy.Router{
		proxy.AdvertisedName("d", "act"): {Recipe: rec, RecipeHash: "h", RecipeName: "p",
			GateArg: "topic,node", Server: "d", Tool: "act"},
	}}
	srv := mcpgate.NewGatingServer(gate,
		mcpgate.NewFleet([]mcpgate.Downstream{{Name: "d", Session: downstream,
			Tools: []*mcp.Tool{{Name: "act", Description: "act", InputSchema: schema}}}}),
		mcpgate.ReadChannel{
			Providers: []provider.ContextProvider{ctxProv2{"runbooks"}},
			Record:    func(_ context.Context, e provider.ReadEvent) { reads = append(reads, e) },
		})
	ac, as := mcp.NewInMemoryTransports()
	gs, err := srv.Connect(ctx, as, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gs.Close() })
	agent := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil)
	sess, err := agent.Connect(ctx, ac, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return ctx, sess, &reads
}

type ctxProv2 struct{ name string }

func (c ctxProv2) Name() string { return c.name }
func (c ctxProv2) Provide(_ context.Context, q string) ([]provider.ContextItem, error) {
	return []provider.ContextItem{{Source: "runbook-3", Text: "RUNBOOK: cordon first (" + q + ")"}}, nil
}

func allText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// The context arrives with the action's result — the agent asked for neither.
func TestRecipeReadArrivesWithTheResult(t *testing.T) {
	ctx, sess, reads := readStepRig(t, "kind-worker")
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      proxy.AdvertisedName("d", "act"),
		Arguments: json.RawMessage(`{"topic":"drain","node":"kind-worker"}`)})
	if err != nil {
		t.Fatal(err)
	}
	txt := allText(res)
	if !strings.Contains(txt, "RUNBOOK: cordon first") {
		t.Errorf("the recipe's read must reach the agent: %q", txt)
	}
	if !strings.Contains(txt, "ACTION-RESULT") {
		t.Errorf("and the action's own result must still be there: %q", txt)
	}
	if !strings.Contains(txt, "untrusted context") {
		t.Error("the context must carry its untrusted label")
	}
	if len(*reads) != 1 || (*reads)[0].Query != "drain" {
		t.Errorf("the read must be recorded with its gated query: %+v", *reads)
	}
}

// A REFUSED action still delivers the context that explains it.
func TestReadArrivesEvenWhenTheActionIsRefused(t *testing.T) {
	ctx, sess, reads := readStepRig(t, "kind-worker")
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      proxy.AdvertisedName("d", "act"),
		Arguments: json.RawMessage(`{"topic":"drain","node":"kind-control-plane"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("the action must be refused")
	}
	txt := allText(res)
	if !strings.Contains(txt, "RUNBOOK: cordon first") {
		t.Errorf("a refusal must still carry the context explaining it: %q", txt)
	}
	if len(*reads) != 1 {
		t.Error("and the read must still be recorded")
	}
}

// The model cannot widen the question: an ungated topic authorizes no read, and the action is
// judged on its own terms.
func TestModelCannotWidenTheRecipesQuestion(t *testing.T) {
	ctx, sess, reads := readStepRig(t, "kind-worker")
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      proxy.AdvertisedName("d", "act"),
		Arguments: json.RawMessage(`{"topic":"everything about credentials","node":"kind-worker"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Error("a refused read query must not deny the action")
	}
	if len(*reads) != 0 {
		t.Errorf("no read may be performed for an ungated question: %+v", *reads)
	}
	if strings.Contains(allText(res), "RUNBOOK") {
		t.Error("and no context may be returned")
	}
}
