package mcpgate_test

// kw-test: the per-session crossing budget (Planning/34 §6.2) enforced END TO END through the gating
// server — a real agent making real tool calls. N forwarded crossings, then fail closed; denies and
// escalates (no crossing) never consume the budget.

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// actRouter routes one tool "act" on server "ops" to a recipe that allows text=="ok" and denies the rest.
func actRouter(t *testing.T) proxy.Router {
	t.Helper()
	p, err := recipe.Parse([]byte(`recipe: act
version: 1
rules:
  ok: {kind: set_membership, set: ["ok"]}
steps:
  - {id: p, kind: propose, out: text}
  - {id: s, kind: sink, in: text, field: ops.act, sensitivity: authoritative, rule: ok, actor: "policy:x"}`))
	if err != nil {
		t.Fatal(err)
	}
	return proxy.Router{proxy.AdvertisedName("ops", "act"): {
		Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "ops", Tool: "act",
	}}
}

func TestCrossingBudgetCapsForwardedCrossings(t *testing.T) {
	ctx := context.Background()
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{server(t, ctx, "ops", "act")})
	gate := proxy.Gate{Routes: actRouter(t), Budget: proxy.NewCrossingBudget(2)}
	agent := connectAgent(t, ctx, mcpgate.NewGatingServer(gate, fleet, mcpgate.ReadChannel{}))
	adv := proxy.AdvertisedName("ops", "act")

	forwarded := func(text string) bool {
		res, cerr := agent.CallTool(ctx, &mcp.CallToolParams{Name: adv, Arguments: map[string]any{"text": text}})
		if cerr != nil {
			return false
		}
		return !res.IsError
	}

	// two allowed crossings consume the budget of 2.
	if !forwarded("ok") {
		t.Fatal("crossing 1 (allowed value) must forward")
	}
	if !forwarded("ok") {
		t.Fatal("crossing 2 (allowed value) must forward")
	}
	// the THIRD is refused by the session budget, even though the value itself is allowed — the leakage
	// cap N is enforced at the gate, not left to the client's honour.
	if forwarded("ok") {
		t.Fatal("crossing 3 must be REFUSED by the per-session crossing budget")
	}
}

func TestCrossingBudgetIgnoresNonCrossings(t *testing.T) {
	ctx := context.Background()
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{server(t, ctx, "ops", "act")})
	gate := proxy.Gate{Routes: actRouter(t), Budget: proxy.NewCrossingBudget(1)}
	agent := connectAgent(t, ctx, mcpgate.NewGatingServer(gate, fleet, mcpgate.ReadChannel{}))
	adv := proxy.AdvertisedName("ops", "act")

	forwarded := func(text string) bool {
		res, cerr := agent.CallTool(ctx, &mcp.CallToolParams{Name: adv, Arguments: map[string]any{"text": text}})
		if cerr != nil {
			return false
		}
		return !res.IsError
	}

	// two DENIED calls (value out of set) — neither crosses, so neither may spend the budget of 1.
	if forwarded("nope") {
		t.Fatal("an out-of-set value must be denied")
	}
	if forwarded("still-nope") {
		t.Fatal("an out-of-set value must be denied")
	}
	// the budget is intact: the allowed crossing forwards despite the prior denials.
	if !forwarded("ok") {
		t.Fatal("denied calls must NOT consume the crossing budget — the allowed crossing must still forward")
	}
	// and now the single crossing is spent.
	if forwarded("ok") {
		t.Fatal("the budget of 1 is now spent; the next allowed crossing must be refused")
	}
}
