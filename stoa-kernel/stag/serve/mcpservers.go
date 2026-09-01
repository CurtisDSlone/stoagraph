package serve

// file-kw: mcp server endpoints add discover list delete adapters act-channel downstream

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// kw: mcp tool view name schema
type MCPToolView struct {
	Name        string `json:"name"`
	InputSchema string `json:"inputSchema,omitempty"`
}

// kw: mcp server view name transport target enabled tools discover-error auth
type MCPServerView struct {
	Name          string        `json:"name"`
	Transport     string        `json:"transport"`
	Target        string        `json:"target"`
	Enabled       bool          `json:"enabled"`
	Tools         []MCPToolView `json:"tools"`
	DiscoverError string        `json:"discoverError,omitempty"`
	// downstream auth — the raw secret is NEVER echoed, only whether one is present + a masked hint.
	AuthScheme  string `json:"authScheme,omitempty"`
	AuthHeader  string `json:"authHeader,omitempty"`
	SecretEnv   string `json:"secretEnv,omitempty"`
	SecretSet   bool   `json:"secretSet"`
	SecretHint  string `json:"secretHint,omitempty"`
	OAuthConfig string `json:"oauthConfig,omitempty"`
}

func serverView(srv store.MCPServer, discoverErr string) MCPServerView {
	v := MCPServerView{
		Name: srv.Name, Transport: srv.Transport, Target: srv.Target, Enabled: srv.Enabled, DiscoverError: discoverErr,
		AuthScheme: srv.AuthScheme, AuthHeader: srv.AuthHeader, SecretEnv: srv.SecretEnv,
		SecretSet: srv.Secret != "", SecretHint: maskSecret(srv.Secret), OAuthConfig: nonEmptyJSON(srv.OAuthConfig),
	}
	v.Tools = make([]MCPToolView, 0, len(srv.Tools))
	for _, tl := range srv.Tools {
		v.Tools = append(v.Tools, MCPToolView{Name: tl.Name, InputSchema: tl.InputSchema})
	}
	return v
}

// maskSecret returns a non-revealing hint of a stored secret (its last 4 chars), never the value.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > 4 {
		return "…" + s[len(s)-4:]
	}
	return "…"
}

func nonEmptyJSON(s string) string {
	if s == "" || s == "{}" {
		return ""
	}
	return s
}

// GET /api/mcp-servers — the configured downstream servers with their discovered tools.
func (s *Server) handleMCPList(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, []MCPServerView{})
		return
	}
	servers, err := s.Store.ListMCPServers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	out := make([]MCPServerView, 0, len(servers))
	for _, srv := range servers {
		out = append(out, serverView(srv, ""))
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/mcp-servers — {name, transport, target, enabled}; stores the server and,
// if discovery is wired, connects to it and persists its tools. A discovery failure
// still stores the server (unreachable) and is reported in discoverError.
func (s *Server) handleMCPPut(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Name        string `json:"name"`
		Transport   string `json:"transport"`
		Target      string `json:"target"`
		Enabled     *bool  `json:"enabled"`
		AuthScheme  string `json:"authScheme"`
		AuthHeader  string `json:"authHeader"`
		Secret      string `json:"secret"`    // empty on edit preserves the stored secret
		SecretEnv   string `json:"secretEnv"` // preferred: env var name, not the secret
		OAuthConfig string `json:"oauthConfig"`
	}
	if json.Unmarshal(body, &req) != nil || req.Name == "" || req.Target == "" {
		writeJSON(w, http.StatusBadRequest, errObj("server needs a name and target"))
		return
	}
	// The server name becomes half of every advertised tool name (<server>__<tool>), which is handed to
	// a model verbatim. Reject anything the provider tool-use APIs would refuse (^[a-zA-Z0-9_-]+$), and
	// reject a name containing the "__" separator, which would make the advertised name ambiguous to
	// split. Caught here, at authoring time, rather than mangled silently at advertise time.
	if !proxy.ValidServerName(req.Name) {
		writeJSON(w, http.StatusBadRequest, errObj(
			`server name must match [a-zA-Z0-9_-]+ and must not contain "__" (it prefixes every tool name the agent sees)`))
		return
	}
	// sse is the LEGACY MCP remote transport; a large part of the deployed ecosystem still speaks only
	// that, so refusing it would put those servers out of reach for no good reason.
	if req.Transport != "stdio" && req.Transport != "http" && req.Transport != "sse" {
		writeJSON(w, http.StatusBadRequest, errObj(`transport must be "stdio", "http" (streamable) or "sse" (legacy)`))
		return
	}
	scheme := req.AuthScheme
	if scheme == "" {
		scheme = "none"
	}
	if scheme != "none" && scheme != "bearer" && scheme != "header" && scheme != "query" && scheme != "oauth" {
		writeJSON(w, http.StatusBadRequest, errObj(`authScheme must be none | bearer | header | query | oauth`))
		return
	}
	if scheme == "query" && req.AuthHeader == "" {
		writeJSON(w, http.StatusBadRequest, errObj(`query auth needs a parameter name (authHeader), e.g. "apikey"`))
		return
	}
	srv := store.MCPServer{
		Name: req.Name, Transport: req.Transport, Target: req.Target, Enabled: req.Enabled == nil || *req.Enabled,
		AuthScheme: scheme, AuthHeader: req.AuthHeader, Secret: req.Secret, SecretEnv: req.SecretEnv, OAuthConfig: req.OAuthConfig,
	}
	// Editing without re-entering the secret preserves it — the store keeps it on write, but
	// discovery (below) runs first, so pull the stored secret into memory for the connect too.
	if srv.Secret == "" && s.Store != nil {
		if existing, gerr := s.Store.GetMCPServer(r.Context(), srv.Name); gerr == nil {
			srv.Secret = existing.Secret
		}
	}

	discoverErr := ""
	if s.Discover != nil {
		tools, derr := s.Discover(r.Context(), srv)
		if derr != nil {
			discoverErr = derr.Error() // unreachable: store the server, no tools, report why
		} else {
			srv.Tools = tools
		}
	}
	if err := s.Store.PutMCPServer(r.Context(), srv); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, serverView(srv, discoverErr))
}

// DELETE /api/mcp-servers/{name}
func (s *Server) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	if err := s.Store.DeleteMCPServer(r.Context(), r.PathValue("name")); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("name")})
}
