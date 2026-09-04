package mcpgate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
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

// memAuthz is a minimal in-memory grant store for the sequenced-route tests. Redeem holds the
// lock across find-and-remove: a check-then-spend pair can double-spend a one-shot grant.
type memAuthz struct {
	mu   sync.Mutex
	live map[string]proxy.Grant
}

func (m *memAuthz) Mint(_ context.Context, g proxy.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live == nil {
		m.live = map[string]proxy.Grant{}
	}
	m.live[g.Fingerprint] = g
	return nil
}

func (m *memAuthz) Redeem(_ context.Context, fp, session string) (proxy.Grant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.live[fp]
	if !ok || g.Session != session {
		return proxy.Grant{}, false, nil
	}
	delete(m.live, fp)
	return g, true, nil
}

func (m *memAuthz) Restore(_ context.Context, g proxy.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.live[g.Fingerprint] = g
	return nil
}

func (m *memAuthz) Sweep(_ context.Context, session, run string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for fp, g := range m.live {
		if g.Session == session && g.Run == run {
			delete(m.live, fp)
		}
	}
	return nil
}

func planTestRigSequenced(t *testing.T) (context.Context, *mcp.ClientSession, *[]string) {
	return buildPlanRig(t, true)
}

func planTestRig(t *testing.T) (context.Context, *mcp.ClientSession, *[]string) {
	return buildPlanRig(t, false)
}

func buildPlanRig(t *testing.T, sequenced bool) (context.Context, *mcp.ClientSession, *[]string) {
	return buildPlanRigSink(t, sequenced, nil)
}

// recFn is a Sink that hands each decision record to a callback.
type recFn func(stag.DecisionRecord)

func (f recFn) Record(_ context.Context, r stag.DecisionRecord) error { f(r); return nil }

func buildPlanRigSink(t *testing.T, sequenced bool, onRec func(stag.DecisionRecord)) (context.Context, *mcp.ClientSession, *[]string) {
	t.Helper()
	ctx := context.Background()
	var ran []string
	var ranMu sync.Mutex // the downstream handler is entered concurrently by parallel sequences

	var schema any = json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	var planSchema any = json.RawMessage(`{"type":"object","properties":{"which":{"type":"string"}},"required":["which"]}`)

	down := mcp.NewServer(&mcp.Implementation{Name: "d", Version: "0"}, nil)
	for _, n := range []string{"step_one", "step_two"} {
		name := n
		down.AddTool(&mcp.Tool{Name: name, Description: name, InputSchema: schema},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var m map[string]any
				_ = json.Unmarshal(req.Params.Arguments, &m)
				ranMu.Lock()
				ran = append(ran, fmt.Sprintf("%s(%v)", name, m["name"]))
				ranMu.Unlock()
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok:" + name}}}, nil
			})
	}
	// the PLAN tool: it takes the proposal and has no downstream work of its own
	down.AddTool(&mcp.Tool{Name: "do_plan", Description: "plan", InputSchema: planSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ranMu.Lock()
			ran = append(ran, "PLAN-TOOL-ITSELF-RAN")
			ranMu.Unlock()
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
			RecipeName: "step_policy", GateArg: "name", Server: "d", Tool: n, Sequenced: sequenced}
	}
	gate := proxy.Gate{Routes: routes, Authorizations: &memAuthz{}}
	if onRec != nil {
		gate.Sink = recFn(onRec)
	}

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

// A SEQUENCED tool is not offered to the agent and is unreachable without a live grant. The
// sequence still executes it, because the executor mints a one-shot grant for exactly that
// call — so the model cannot name what it cannot see, AND cannot reach it by guessing.
func TestSequencedToolIsHiddenAndUnreachable(t *testing.T) {
	ctx, sess, ran := planTestRigSequenced(t)

	// 1. it is NOT advertised
	lst, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range lst.Tools {
		if tl.Name == proxy.AdvertisedName("d", "step_one") {
			t.Fatal("a sequenced tool must not be offered to the agent")
		}
	}

	// 2. calling it directly by name is DENIED, not merely unlisted
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "step_one"), Arguments: json.RawMessage(`{"name":"alpha"}`)})
	if err == nil && res != nil && !res.IsError {
		t.Fatal("guessing the name of a sequenced tool must be refused")
	}
	if len(*ran) != 0 {
		t.Fatalf("nothing may run from a direct call: %v", *ran)
	}

	// 3. the SEQUENCE still executes it
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"alpha"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("the authorized sequence must run: %+v", res.Content)
	}
	if len(*ran) != 2 {
		t.Fatalf("the sequence must reach the sequenced tools: %v", *ran)
	}
}

// A direct call to a SEQUENCED tool must be RECORDED, not silently 404'd. "The agent reached
// for a tool it was never offered" is precisely the evidence an auditor wants, and it is more
// suspicious than an unrouted call, not less — the name had to come from somewhere.
func TestGuessingASequencedToolIsRecorded(t *testing.T) {
	var recorded []stag.DecisionRecord
	ctx, sess, ran := buildPlanRigSink(t, true, func(r stag.DecisionRecord) { recorded = append(recorded, r) })

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: proxy.AdvertisedName("d", "step_one"), Arguments: json.RawMessage(`{"name":"alpha"}`)})
	if err == nil && res != nil && !res.IsError {
		t.Fatal("a guessed sequenced tool must be refused")
	}
	if len(*ran) != 0 {
		t.Fatalf("nothing may run: %v", *ran)
	}
	found := false
	for _, r := range recorded {
		if r.Tool == proxy.AdvertisedName("d", "step_one") && r.Verdict == "deny" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the attempt must be recorded as a denial, got %d record(s)", len(recorded))
	}
}

// The end-of-sequence sweep must not disturb a CONCURRENT sequence on the same session. Sweep
// is scoped to a session, and two sequences can share one — so a naive sweep would delete the
// other sequence's outstanding grant mid-flight.
func TestConcurrentSequencesOnOneSessionBothComplete(t *testing.T) {
	ctx, sess, ran := planTestRigSequenced(t)
	var wg sync.WaitGroup
	errs := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := sess.CallTool(ctx, &mcp.CallToolParams{
				Name: proxy.AdvertisedName("d", "do_plan"), Arguments: json.RawMessage(`{"which":"alpha"}`)})
			if err != nil {
				errs <- "call error: " + err.Error()
				return
			}
			if res.IsError {
				errs <- "sequence did not complete: " + textOfContent(res)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	// two sequences of two steps each
	if len(*ran) != 4 {
		t.Errorf("both sequences must run every step: %v", *ran)
	}
}

func textOfContent(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
