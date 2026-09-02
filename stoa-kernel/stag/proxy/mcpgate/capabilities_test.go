package mcpgate_test

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A capability is a promise. The SDK infers listChanged:true the moment a tool is added, but a
// session's tool surface is fixed at BIND — the compiled router never changes — so the notification
// can never fire. A client that believes the promise caches its tool list forever and never re-lists,
// which looks to an operator like "the backend is stuck" when the truth is "that surface belongs to a
// new binding". Advertising a capability we do not implement makes correct clients behave incorrectly.
func TestServerDoesNotPromiseToolListChanged(t *testing.T) {
	ctx := context.Background()
	srv := mcpgate.NewGatingServer(proxy.Gate{Routes: proxy.Router{}}, mcpgate.NewFleet(nil), mcpgate.ReadChannel{})

	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	caps := cs.InitializeResult().Capabilities
	if caps.Tools != nil && caps.Tools.ListChanged {
		t.Error("the gate advertised tools.listChanged=true but never sends the notification — " +
			"a client that trusts it will cache a stale tool list for the life of its session")
	}
}
