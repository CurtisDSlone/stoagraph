package mcpgate_test

// kw-test: the ROUTE picks the server — a cleared call reaches the downstream that owns the tool

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// server stands up a downstream exposing `tools`, each echoing which SERVER handled it.
func server(t *testing.T, ctx context.Context, name string, tools ...string) mcpgate.Downstream {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: name, Version: "0"}, nil)
	for _, tl := range tools {
		srv.AddTool(&mcp.Tool{Name: tl, Description: tl, InputSchema: noteSchema},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "handled by " + name}}}, nil
			})
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "stag", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	decls := make([]*mcp.Tool, len(tools))
	for i, tl := range tools {
		decls[i] = &mcp.Tool{Name: tl, Description: tl, InputSchema: noteSchema}
	}
	return mcpgate.Downstream{Name: name, Session: sess, Tools: decls}
}

// TestRoutePicksTheServer is the multi-downstream guarantee. A GitHub server and a local tool server
// reach ONE agent, and each cleared call must land on the server that owns that tool — not on whichever
// happened to connect first. Nothing extra decides this: the route names the tool, the tool has an
// owner, and that is the dispatch.
func TestRoutePicksTheServer(t *testing.T) {
	ctx := context.Background()
	gh := server(t, ctx, "GH", "get_file_contents", "delete_file")
	local := server(t, ctx, "local-tools", "read_file", "search_code")

	p, err := recipe.Parse([]byte(policySrc))
	if err != nil {
		t.Fatal(err)
	}
	// route ONE tool from EACH server — each route NAMES its server, and is keyed by the ADVERTISED name
	gate := proxy.Gate{Routes: proxy.Router{
		proxy.AdvertisedName("GH", "get_file_contents"):  {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "GH", Tool: "get_file_contents"},
		proxy.AdvertisedName("local-tools", "read_file"): {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "local-tools", Tool: "read_file"},
	}}
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{gh, local})

	agent := connectAgent(t, ctx, mcpgate.NewGatingServer(gate, fleet, mcpgate.ReadChannel{}))

	// the agent sees exactly the routed tools, under their NAMESPACED names — one from each server
	list, err := agent.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tl := range list.Tools {
		got[tl.Name] = true
	}
	if len(list.Tools) != 2 || !got["GH__get_file_contents"] || !got["local-tools__read_file"] {
		t.Fatalf("agent must be offered exactly the two routed tools, one per server; got %v", got)
	}

	// and each call reaches ITS OWN server. The agent calls the advertised name; the DOWNSTREAM is
	// called under its own tool name, which is why these handlers answer at all.
	for tool, want := range map[string]string{
		"GH__get_file_contents":  "handled by GH",
		"local-tools__read_file": "handled by local-tools",
	} {
		res, cerr := agent.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"text": "hello"}})
		if cerr != nil {
			t.Fatalf("%s: %v", tool, cerr)
		}
		if res.IsError {
			t.Fatalf("%s was refused: %s", tool, textOf(t, res))
		}
		if got := textOf(t, res); got != want {
			t.Fatalf("%s went to the WRONG server: got %q, want %q", tool, got, want)
		}
	}
}

// TestRouteDelegatesWhenTwoServersShareAToolName is why the SERVER belongs in the route, and why the
// advertised tool surface is NAMESPACED.
//
// Both servers expose `search_code`, and BOTH are routed AT THE SAME TIME. This is the case the gate
// used to be unable to express: the router was keyed by tool name, so the second route overwrote the
// first and silently repointed it at the other server — a policy quietly changing because you added a
// server, which is exactly what this product exists to prevent. Keying on <server>__<tool> makes the
// two distinct tools, each bound to its own recipe and each dispatched where its route says.
func TestRouteDelegatesWhenTwoServersShareAToolName(t *testing.T) {
	ctx := context.Background()
	alpha := server(t, ctx, "alpha", "search_code")
	beta := server(t, ctx, "beta", "search_code")
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{alpha, beta})

	p, _ := recipe.Parse([]byte(policySrc))

	// the SAME tool name on BOTH servers, both routed — the thing the old key made impossible
	gate := proxy.Gate{Routes: proxy.Router{
		proxy.AdvertisedName("alpha", "search_code"): {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "alpha", Tool: "search_code"},
		proxy.AdvertisedName("beta", "search_code"):  {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "beta", Tool: "search_code"},
	}}
	agent := connectAgent(t, ctx, mcpgate.NewGatingServer(gate, fleet, mcpgate.ReadChannel{}))

	// the agent is offered BOTH, told apart by their server prefix
	list, err := agent.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tl := range list.Tools {
		got[tl.Name] = true
	}
	if len(list.Tools) != 2 || !got["alpha__search_code"] || !got["beta__search_code"] {
		t.Fatalf("both servers' search_code must be offered, told apart by prefix; got %v", got)
	}

	// and each one dispatches to ITS OWN server — neither route repointed the other
	for tool, want := range map[string]string{
		"alpha__search_code": "handled by alpha",
		"beta__search_code":  "handled by beta",
	} {
		res, cerr := agent.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"text": "hello"}})
		if cerr != nil {
			t.Fatalf("%s: %v", tool, cerr)
		}
		if res.IsError {
			t.Fatalf("%s was refused: %s", tool, textOf(t, res))
		}
		if got := textOf(t, res); got != want {
			t.Fatalf("%s went to the WRONG server: got %q, want %q", tool, got, want)
		}
	}
}

// TestRouteToAnUnknownServerIsNotServed — a route naming a server that is not connected, or a tool that
// server does not expose, must never be advertised. Fail closed, and say so at bind.
func TestRouteToAnUnknownServerIsNotServed(t *testing.T) {
	ctx := context.Background()
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{server(t, ctx, "alpha", "search_code")})
	p, _ := recipe.Parse([]byte(policySrc))

	for _, rt := range []proxy.Route{
		{Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "ghost", Tool: "not_there"}, // no such server
		{Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "alpha", Tool: "not_there"}, // server exists, tool does not
	} {
		gate := proxy.Gate{Routes: proxy.Router{proxy.AdvertisedName(rt.Server, rt.Tool): rt}}
		agent := connectAgent(t, ctx, mcpgate.NewGatingServer(gate, fleet, mcpgate.ReadChannel{}))
		list, err := agent.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Tools) != 0 {
			t.Fatalf("an undispatchable route must never be advertised, got %d tools", len(list.Tools))
		}
	}

	// and the fleet says exactly why
	if _, _, err := fleet.Lookup("ghost", "search_code"); err == nil {
		t.Fatal("an unconnected server must be an error, not a guess")
	}
	if _, _, err := fleet.Lookup("alpha", "nope"); err == nil {
		t.Fatal("a tool the server does not expose must be an error, not a guess")
	}
}

func connectAgent(t *testing.T, ctx context.Context, gating *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := gating.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	return agent
}
