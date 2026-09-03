package mcpgate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An agent that calls a PLAN tool over MCP gets the whole authorized sequence executed, with
// every call re-crossing the gate. This is the seam that makes `invoke` reachable from a real
// agent session rather than only from a driver.

const planPolicy = `
recipe: plan_policy
version: 1
rules:
  step.ok: {kind: set_membership, set: ["alpha", "beta"]}
steps:
  - {id: p, kind: propose, out: which}
  - {id: one, kind: invoke, tool: d__step_one, args: {name: {slot: which, rule: step.ok}}, actor: "policy:test"}
  - {id: two, kind: invoke, tool: d__step_two, args: {name: {slot: which, rule: step.ok}}, actor: "policy:test"}
`

// the target policy each step re-crosses: TIGHTER than the plan's, to prove the plan cannot
// launder a value the target refuses.
const stepPolicy = `
recipe: step_policy
version: 1
rules:
  tight: {kind: set_membership, set: ["alpha"]}
steps:
  - {id: p, kind: propose, out: name}
  - {id: s, kind: sink, in: name, field: step.name, sensitivity: authoritative, rule: tight, actor: "policy:step"}
`

func planTestRig(t *testing.T) (context.Context, *mcp.ClientSession, *[]string) {
	t.Helper()
	ctx := context.Background()
	var ran []string

	var schema any = json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	var planSchema any = json.RawMessage(`{"type":"object","properties":{"which":{"type":"string"}},"required":["which"]}`)

	down := mcp.NewServer(&mcp.Implementation{Name: "d", Version: "0"}, nil)
	for _, n := range []string{"step_one", "step_two"} {
		name := n
		down.AddTool(&mcp.Tool{Name: name, Description: name, InputSchema: schema},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var m map[string]any
				_ = json.Unmarshal(req.Params.Arguments, &m)
				ran = append(ran, fmt.Sprintf("%s(%v)", name, m["name"]))
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok:" + name}}}, nil
			})
	}
	// the PLAN tool: it takes the proposal and has no downstream work of its own
	down.AddTool(&mcp.Tool{Name: "do_plan", Description: "plan", InputSchema: planSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ran = append(ran, "PLAN-TOOL-ITSELF-RAN")
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "plan"}}}, nil
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

	plan, err := recipe.Parse([]byte(planPolicy))
	if err != nil {
		t.Fatal(err)
	}
	step, err := recipe.Parse([]byte(stepPolicy))
	if err != nil {
		t.Fatal(err)
	}

	routes := proxy.Router{
		proxy.AdvertisedName("d", "do_plan"): {Recipe: plan.Recipe, RecipeHash: plan.SemanticHash,
			RecipeName: "plan_policy", GateArg: "which", Server: "d", Tool: "do_plan"},
	}
	for _, n := range []string{"step_one", "step_two"} {
		routes[proxy.AdvertisedName("d", n)] = proxy.Route{Recipe: step.Recipe, RecipeHash: step.SemanticHash,
			RecipeName: "step_policy", GateArg: "name", Server: "d", Tool: n}
	}
	gate := proxy.Gate{Routes: routes}

	tools := []*mcp.Tool{
		{Name: "do_plan", Description: "plan", InputSchema: planSchema},
		{Name: "step_one", Description: "one", InputSchema: schema},
		{Name: "step_two", Description: "two", InputSchema: schema},
	}
	srv := mcpgate.NewGatingServer(gate,
		mcpgate.NewFleet([]mcpgate.Downstream{{Name: "d", Session: downstream, Tools: tools}}),
		mcpgate.ReadChannel{})
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
	return ctx, sess, &ran
}

// The whole authorized sequence runs, in order, from ONE agent call.
func TestAgentPlanCallExecutesSequence(t *testing.T) {
	ctx, sess, ran := planTestRig(t)
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"alpha"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("allowed plan must not error: %+v", res.Content)
	}
	if len(*ran) != 2 || (*ran)[0] != "step_one(alpha)" || (*ran)[1] != "step_two(alpha)" {
		t.Fatalf("the authorized sequence must run in order: %v", *ran)
	}
}

// The plan tool itself is NOT forwarded downstream: a plan authorizes calls, it is not a call.
func TestPlanToolIsNotItselfForwarded(t *testing.T) {
	ctx, sess, ran := planTestRig(t)
	_, _ = sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"alpha"}`)})
	for _, r := range *ran {
		if r == "PLAN-TOOL-ITSELF-RAN" {
			t.Fatal("a plan recipe must not also forward its own tool downstream")
		}
	}
}

// The target policy still fires: "beta" clears the PLAN's rule but not the STEP's, so the
// sequence halts at the first call and nothing runs.
func TestPlanCannotLaunderAValueTheStepRefuses(t *testing.T) {
	ctx, sess, ran := planTestRig(t)
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"beta"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(*ran) != 0 {
		t.Fatalf("nothing may run when the step policy refuses: %v", *ran)
	}
	if !res.IsError {
		t.Error("the agent must be told the sequence did not complete")
	}
}

// A denied plan authorizes nothing and runs nothing.
func TestDeniedPlanRunsNothing(t *testing.T) {
	ctx, sess, ran := planTestRig(t)
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"evil"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || len(*ran) != 0 {
		t.Fatalf("denied plan: err=%v ran=%v", res.IsError, *ran)
	}
}

// The agent is told what happened: the result names the steps and where it stopped.
func TestSequenceResultIsReportedToTheAgent(t *testing.T) {
	ctx, sess, _ := planTestRig(t)
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"alpha"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "step_one") || !strings.Contains(text, "step_two") {
		t.Errorf("the agent must see which steps ran: %q", text)
	}
}
