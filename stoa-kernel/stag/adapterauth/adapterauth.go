// Package adapterauth resolves a stored MCP server into the connect-time credential the gate injects
// downstream. It is the single place that maps the oauth scheme to a fresh bearer token (refreshing if
// needed); bearer, header, query, and none pass straight through. Keeping this in one leaf package lets
// every connect site (stag-proxy enforcement, stag-serve discovery) share the same resolution without
// duplicating the oauth branch — and without mcpgate needing to know about the token store.
package adapterauth

// file-kw: adapter auth resolve oauth bearer connect credential

import (
	"context"
	"net/http"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// Resolve produces the downstream Auth for srv. For an oauth server it fetches a fresh access token from
// the oauth store (fail-closed: an unauthorized server returns an error, so no half-authenticated
// connect). Every other scheme is a pass-through of the server's static credential.
func Resolve(ctx context.Context, os oauth.Store, hc *http.Client, srv store.MCPServer) (mcpgate.Auth, error) {
	if srv.AuthScheme == "oauth" {
		tok, err := os.Bearer(ctx, hc, srv.Name)
		if err != nil {
			return mcpgate.Auth{}, err
		}
		return mcpgate.Auth{Scheme: "bearer", Credential: tok}, nil
	}
	return mcpgate.Auth{Scheme: srv.AuthScheme, Header: srv.AuthHeader, Credential: srv.Credential()}, nil
}
