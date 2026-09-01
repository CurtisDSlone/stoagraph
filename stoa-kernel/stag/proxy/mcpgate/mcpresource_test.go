package mcpgate_test

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// a tiny downstream MCP server exposing one resource, connected in-memory.
func connectResourceServer(t *testing.T, uri, text string) mcpgate.Downstream {
	t.Helper()
	ctx := context.Background()
	srv := mcp.NewServer(&mcp.Implementation{Name: "docs", Version: "0"}, nil)
	srv.AddResource(&mcp.Resource{URI: uri, Name: "the-doc", MIMEType: "text/plain"},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, Text: text}}}, nil
		})
	cT, sT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, sT, nil); err != nil {
		t.Fatal(err)
	}
	cli := mcp.NewClient(&mcp.Implementation{Name: "gate", Version: "0"}, nil)
	sess, err := cli.Connect(ctx, cT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return mcpgate.Downstream{Name: "docs", Session: sess, Resources: []*mcp.Resource{{URI: uri, Name: "the-doc"}}}
}

// The mcp_resource provider proxies a connected downstream's resource content, and Gather stamps it
// untrusted at origin like any context — a downstream doc informs the model, it cannot instruct it.
func TestMCPResourceProxiesAndStampsUntrusted(t *testing.T) {
	d := connectResourceServer(t, "file:///runbook.md", "to remediate: restart the pod")
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{d})

	p, err := mcpgate.NewMCPResourceProvider(fleet, "runbooks", `{"server":"docs"}`)
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	items, errs := provider.Gather(context.Background(), "ignored query", []provider.ContextProvider{p})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(items) != 1 || items[0].Text != "to remediate: restart the pod" {
		t.Fatalf("expected the downstream resource content; got %+v", items)
	}
	if items[0].Trust != provider.Untrusted {
		t.Fatalf("downstream resource must be stamped untrusted; got %q", items[0].Trust)
	}
}

// A specific URI can be selected; a wrong URI fails open per-resource (empty, not an error).
func TestMCPResourceSelectsConfiguredURI(t *testing.T) {
	d := connectResourceServer(t, "file:///a.md", "alpha")
	fleet := mcpgate.NewFleet([]mcpgate.Downstream{d})
	p, err := mcpgate.NewMCPResourceProvider(fleet, "sel", `{"server":"docs","uris":["file:///a.md"]}`)
	if err != nil {
		t.Fatal(err)
	}
	items, _ := provider.Gather(context.Background(), "", []provider.ContextProvider{p})
	if len(items) != 1 || items[0].Text != "alpha" {
		t.Fatalf("configured uri must be read: %+v", items)
	}
}

// Fail closed: an unconnected server, a missing server field, or a server with no resources errors at
// build (the caller then DROPS it — never fabricates a source).
func TestMCPResourceFailsClosed(t *testing.T) {
	empty := mcpgate.NewFleet(nil)
	if _, err := mcpgate.NewMCPResourceProvider(empty, "x", `{"server":"nope"}`); err == nil {
		t.Fatal("an unconnected server must error")
	}
	if _, err := mcpgate.NewMCPResourceProvider(empty, "x", `{}`); err == nil {
		t.Fatal("a missing server field must error")
	}
	// a connected server exposing NO resources, with none configured
	noRes := mcpgate.NewFleet([]mcpgate.Downstream{{Name: "docs"}})
	if _, err := mcpgate.NewMCPResourceProvider(noRes, "x", `{"server":"docs"}`); err == nil {
		t.Fatal("a server with no resources and no configured uris must error")
	}
}
