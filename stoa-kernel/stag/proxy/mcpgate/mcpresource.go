package mcpgate

// file-kw: mcp_resource context provider proxy downstream resources read untrusted quarantine c4

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

// mcpResourceProvider proxies a connected downstream MCP server's resources as a READ-channel context
// provider (Planning/33, C4). It lives in mcpgate — not in the (MCP-free) provider package — so the
// quarantine holds: only this adapter layer speaks MCP. It satisfies provider.ContextProvider, so the
// gate serves it exactly like an http/static provider (queryable template, stamped untrusted at
// origin by Gather, recorded with per-item content hashes).
//
// A read reads the configured resource URIs (or, if none was configured, every resource the server
// discovered at connect). The query is not passed to the downstream: MCP resources are URI-addressed,
// not searched, so — like a static bundle — an mcp_resource provider has no outbound `?q` and thus no
// READ-side egress. Per-resource fail-open: an unreadable resource is skipped, the rest still return.
type mcpResourceProvider struct {
	name    string
	session *mcp.ClientSession
	uris    []string
}

func (p mcpResourceProvider) Name() string { return p.name }

func (p mcpResourceProvider) Provide(ctx context.Context, _ string) ([]provider.ContextItem, error) {
	var items []provider.ContextItem
	for _, uri := range p.uris {
		res, err := p.session.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil || res == nil {
			continue // fail-open per resource: a bad one does not sink the whole read
		}
		for _, c := range res.Contents {
			if c.Text == "" {
				continue
			}
			items = append(items, provider.ContextItem{Source: p.name + ":" + c.URI, Text: c.Text})
		}
	}
	return items, nil
}

// NewMCPResourceProvider builds an mcp_resource context provider from a connected server in the fleet
// (C4). Config: {"server":"<downstream name>","uris":["<uri>",...]}. An empty uris list means "every
// resource the server discovered at connect". Fail-closed: an unconnected server, bad config, or a
// server with no resources and no configured uris is an error — the caller (sessiond) then DROPS the
// provider and logs it, never fabricating a source.
func NewMCPResourceProvider(fleet Fleet, name, config string) (provider.ContextProvider, error) {
	var c struct {
		Server string   `json:"server"`
		URIs   []string `json:"uris"`
	}
	if config != "" {
		if err := json.Unmarshal([]byte(config), &c); err != nil {
			return nil, fmt.Errorf("provider %s: mcp_resource config: %w", name, err)
		}
	}
	if c.Server == "" {
		return nil, fmt.Errorf("provider %s: mcp_resource config needs a server", name)
	}
	d, ok := fleet.Server(c.Server)
	if !ok {
		return nil, fmt.Errorf("provider %s: mcp_resource server %q is not connected", name, c.Server)
	}
	uris := c.URIs
	if len(uris) == 0 { // default: every resource the server discovered at connect
		for _, r := range d.Resources {
			uris = append(uris, r.URI)
		}
	}
	if len(uris) == 0 {
		return nil, fmt.Errorf("provider %s: mcp_resource server %q exposes no resources and none were configured", name, c.Server)
	}
	return mcpResourceProvider{name: name, session: d.Session, uris: uris}, nil
}
