package mcpgate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
)

// connect stands up an in-memory downstream and returns stag's client session to it plus a closer
// that kills the server side, simulating the downstream dying after the fleet was built.
func connect(t *testing.T, ctx context.Context, name string) (*mcp.ClientSession, func()) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: name, Version: "0"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stag", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, func() { _ = ss.Close() }
}

func TestFleetPingEmptyIsNotReady(t *testing.T) {
	if err := mcpgate.NewFleet(nil).Ping(context.Background()); err == nil {
		t.Fatal("a fleet with nothing to mediate must not report ready")
	}
}

func TestFleetPingReflectsDownstreamLiveness(t *testing.T) {
	ctx := context.Background()
	a, killA := connect(t, ctx, "alpha")
	b, _ := connect(t, ctx, "beta")
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{{Name: "alpha", Session: a}, {Name: "beta", Session: b}})

	if err := fleet.Ping(ctx); err != nil {
		t.Fatalf("both up: %v", err)
	}

	killA()
	err := fleet.Ping(ctx)
	if err == nil {
		t.Fatal("alpha died; ready must flip back to false, not latch")
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Fatalf("error must name the dead server: %v", err)
	}
	if strings.Contains(err.Error(), "beta") {
		t.Fatalf("beta is healthy and must not be blamed: %v", err)
	}
}
