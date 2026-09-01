package mcpgate_test

// kw-test: the gate advertises ONLY routed tools — an unrouted capability is never offered to the agent

import (
	"context"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// TestAdvertisesOnlyRoutedTools is the GitHub case in miniature: a downstream offering several tools —
// including destructive ones — reaches an agent whose policy routes exactly one. The agent must be
// offered ONE tool. The dangerous ones are not merely denied; they are never named to the model, so a
// prompt-injected document cannot ask for a capability the model has no way to know exists.
func TestAdvertisesOnlyRoutedTools(t *testing.T) {
	ctx := context.Background()

	// a downstream with one governed tool and two destructive ones (cf. GitHub's delete_file)
	downstreamSrv := mcp.NewServer(&mcp.Implementation{Name: "downstream", Version: "0"}, nil)
	for _, name := range []string{"write_note", "delete_file", "create_repository"} {
		downstreamSrv.AddTool(&mcp.Tool{Name: name, Description: name, InputSchema: noteSchema},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{}, nil
			})
	}
	dClientT, dServerT := mcp.NewInMemoryTransports()
	dServerSess, err := downstreamSrv.Connect(ctx, dServerT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dServerSess.Close()
	downstream, err := mcp.NewClient(&mcp.Implementation{Name: "stag-client", Version: "0"}, nil).Connect(ctx, dClientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer downstream.Close()

	// policy routes write_note ONLY
	p, err := recipe.Parse([]byte(policySrc))
	if err != nil {
		t.Fatal(err)
	}
	sink := &recSink{}
	gate := proxy.Gate{Routes: proxy.Router{
		proxy.AdvertisedName("downstream", "write_note"): {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text", Server: "downstream", Tool: "write_note"},
	}, Sink: sink}

	all := []*mcp.Tool{
		{Name: "write_note", Description: "gated write", InputSchema: noteSchema},
		{Name: "delete_file", Description: "DESTRUCTIVE", InputSchema: noteSchema},
		{Name: "create_repository", Description: "DESTRUCTIVE", InputSchema: noteSchema},
	}
	gatingSrv := mcpgate.NewGatingServer(gate,
		mcpgate.NewFleet([]mcpgate.Downstream{{Name: "downstream", Session: downstream, Tools: all}}),
		mcpgate.ReadChannel{})

	aClientT, aServerT := mcp.NewInMemoryTransports()
	gatingSess, err := gatingSrv.Connect(ctx, aServerT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gatingSess.Close()
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, aClientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	res, err := agent.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "downstream__write_note" {
		names := make([]string, 0, len(res.Tools))
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		t.Fatalf("agent must be offered ONLY the routed tool; got %v", names)
	}

	// Naming the hidden tool anyway must be REFUSED — and RECORDED. Hiding it must not make the attempt
	// invisible: an agent reaching for a tool it was never offered is either injected or jailbroken, and
	// that is the loudest signal in the system.
	res2, cerr := agent.CallTool(ctx, &mcp.CallToolParams{
		Name: "delete_file", Arguments: map[string]any{"text": "anything"},
	})
	if cerr != nil {
		t.Fatalf("the gate should refuse at the tool level, not error the protocol: %v", cerr)
	}
	if !res2.IsError {
		t.Fatal("calling an unrouted tool must be refused")
	}
	recs := sink.all()
	if len(recs) != 1 {
		t.Fatalf("the unrouted attempt must be RECORDED (got %d leaves) — hiding a tool must not hide the reach for it", len(recs))
	}
	if d := recs[0]; d.Tool != "delete_file" || d.Verdict != "deny" || d.Forwarded || len(d.Events) != 0 {
		t.Fatalf("unrouted attempt must record a non-forwarded deny with no release: %+v", d)
	}
}

type recSink struct {
	mu   sync.Mutex
	recs []stag.DecisionRecord
}

func (s *recSink) Record(_ context.Context, d stag.DecisionRecord) error {
	s.mu.Lock()
	s.recs = append(s.recs, d)
	s.mu.Unlock()
	return nil
}
func (s *recSink) all() []stag.DecisionRecord { s.mu.Lock(); defer s.mu.Unlock(); return s.recs }
