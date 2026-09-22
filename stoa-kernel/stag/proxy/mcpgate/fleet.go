package mcpgate

// file-kw: fleet downstreams multi-server tool owner route dispatch ambiguous fail-closed

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Downstream is one connected MCP server and the tools it exposes.
// kw: downstream name session tools
type Downstream struct {
	Name    string
	Session *mcp.ClientSession
	Tools   []*mcp.Tool
	// Resources are the server's OWN resources, re-served by the gate as READ channel: labelled
	// untrusted at origin and recorded, never denied. A server whose value is its resources (a repo, a
	// wiki, a doc set) is otherwise invisible to the agent through a tools-only gate.
	Resources []*mcp.Resource
}

// Fleet is every connected downstream, addressed BY NAME.
//
// The gate fronts several tool servers at once and a cleared call must reach the right one. The ROUTE
// says which: a route is tool -> server -> recipe -> gateArg, and the server is part of the binding.
//
// The gate deliberately does NOT work out the server from the tool name. Inference would mean that
// registering an unrelated MCP server could change — or invalidate — a route you already wrote: two
// servers both happen to expose `search_code`, and a route that worked yesterday now resolves somewhere
// else, or nowhere. A policy that quietly changes when you add a server is precisely the surprise this
// product exists to eliminate. The route means the same thing tomorrow as it does today.
//
// So there is no ambiguity to resolve here, and no "owner" to guess: two servers may both expose
// `search_code` and both be routed, because each route names its own server.
// kw: fleet by-name lookup route-declares-server no-inference
type Fleet struct {
	byName map[string]Downstream           // server name -> the connected session
	tools  map[string]map[string]*mcp.Tool // server name -> tool name -> declaration
}

// NewFleet indexes the connected downstreams by NAME.
func NewFleet(downs []Downstream) Fleet {
	f := Fleet{byName: map[string]Downstream{}, tools: map[string]map[string]*mcp.Tool{}}
	for _, d := range downs {
		f.byName[d.Name] = d
		m := map[string]*mcp.Tool{}
		for _, t := range d.Tools {
			m[t.Name] = t
		}
		f.tools[d.Name] = m
	}
	return f
}

// Ping asks every connected downstream whether it is still there. It is the fleet's readiness check,
// and it is what turns "ready" from a latch into a measurement: before this, the daemon flipped ready
// once at connect and never looked again, so a downstream that died at 3am left a gate advertising
// tools it could no longer forward. An empty fleet is not ready: a gate with nothing to mediate must
// not pretend it is mediating. Failures name the server so the operator knows which one is gone.
// kw: fleet ping readiness downstream liveness re-check fail-closed
func (f Fleet) Ping(ctx context.Context) error {
	if len(f.byName) == 0 {
		return errors.New("no downstream MCP server connected")
	}
	names := make([]string, 0, len(f.byName))
	for n := range f.byName {
		names = append(names, n)
	}
	slices.Sort(names) // deterministic error text
	var errs []error
	for _, n := range names {
		if err := f.byName[n].Session.Ping(ctx, nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
		}
	}
	return errors.Join(errs...)
}

// Server resolves a downstream by name (no tool required), for the mcp_resource context provider
// (C4): bind a connected server's resources as a queryable READ-channel provider. Fail-closed — an
// unconnected server is not fabricated.
// kw: fleet server by-name accessor mcp-resource
func (f Fleet) Server(name string) (Downstream, bool) {
	d, ok := f.byName[name]
	return d, ok
}

// Lookup resolves a ROUTE (server + tool) to the connected server and the tool's declaration. It fails
// when the named server is not connected, or when that server does not expose that tool — both of which
// are configuration errors the operator must be told about, never guessed around.
// kw: lookup route server tool declaration fail-closed
func (f Fleet) Lookup(server, tool string) (Downstream, *mcp.Tool, error) {
	d, ok := f.byName[server]
	if !ok {
		return Downstream{}, nil, fmt.Errorf("no connected MCP server named %q", server)
	}
	t, ok := f.tools[server][tool]
	if !ok {
		return Downstream{}, nil, fmt.Errorf("server %q does not expose a tool named %q", server, tool)
	}
	return d, t, nil
}

// Downstreams returns every connected downstream, ordered by name so the advertised surface is stable.
// kw: downstreams all ordered
func (f Fleet) Downstreams() []Downstream {
	out := make([]Downstream, 0, len(f.byName))
	for _, n := range f.Servers() {
		out = append(out, f.byName[n])
	}
	return out
}

// Servers names the connected downstreams.
func (f Fleet) Servers() []string {
	out := make([]string, 0, len(f.byName))
	for name := range f.byName {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
