package serve

// file-kw: oauth start callback status pending pkce sign-in handlers downstream authorization-code

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
)

// pendingOAuth is an in-flight sign-in held between /api/oauth/start and the browser callback.
type pendingOAuth struct {
	server   string
	verifier string
	cfg      oauth.Config
	created  time.Time
}

// serverOAuthConfig is the optional per-server hint (mcp_servers.oauth_config JSON) for providers that
// do NOT support dynamic client registration and need a pre-registered client / explicit scopes.
// serverOAuthConfig is a PROVIDER PROFILE: everything a provider might need beyond what discovery can
// tell us, expressed as DATA on the server record (mcp_servers.oauth_config).
//
// The point is that adding a new provider must never require new code. A spec-compliant MCP server needs
// none of this — discovery + dynamic registration handle it. This exists for the rest of the world:
//
//	no metadata document      -> set authorization_endpoint + token_endpoint (discovery is skipped)
//	no dynamic registration   -> set client_id (+ client_secret)
//	non-standard parameters   -> set authorize_params / token_params (Google's access_type=offline,
//	                             Auth0's audience, Slack's user_scope…)
//	fussy client auth         -> set token_auth_method
//
// Ship one of these per provider as a preset and the "adapter" for a new service is a JSON file.
type serverOAuthConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Issuer       string   `json:"issuer"`

	// Explicit endpoints. Setting authorization+token SKIPS discovery entirely — the escape hatch for a
	// bespoke server that publishes no metadata at all.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`

	TokenAuthMethod string            `json:"token_auth_method"` // client_secret_basic | client_secret_post | none
	AuthorizeParams map[string]string `json:"authorize_params"`
	TokenParams     map[string]string `json:"token_params"`
}

// apply overlays the operator's profile onto whatever discovery found. Discovery is the default; the
// profile is the override — so a provider that lies in (or omits) its metadata can still be driven.
func (oc serverOAuthConfig) apply(cfg oauth.Config) oauth.Config {
	if oc.ClientID != "" {
		cfg.ClientID = oc.ClientID
	}
	if oc.ClientSecret != "" {
		cfg.ClientSecret = oc.ClientSecret
	}
	if len(oc.Scopes) > 0 {
		cfg.Scopes = oc.Scopes
	}
	if oc.Issuer != "" {
		cfg.Issuer = oc.Issuer
	}
	if oc.AuthorizationEndpoint != "" {
		cfg.AuthorizationEndpoint = oc.AuthorizationEndpoint
	}
	if oc.TokenEndpoint != "" {
		cfg.TokenEndpoint = oc.TokenEndpoint
	}
	if oc.RegistrationEndpoint != "" {
		cfg.RegistrationEndpoint = oc.RegistrationEndpoint
	}
	if oc.TokenAuthMethod != "" {
		cfg.TokenAuthMethod = oc.TokenAuthMethod
	}
	if len(oc.AuthorizeParams) > 0 {
		cfg.AuthorizeParams = oc.AuthorizeParams
	}
	if len(oc.TokenParams) > 0 {
		cfg.TokenParams = oc.TokenParams
	}
	return cfg
}

// selfDescribing reports whether the profile names both endpoints itself, in which case there is nothing
// to discover — the provider serves no metadata and the operator has told us where everything lives.
func (oc serverOAuthConfig) selfDescribing() bool {
	return oc.AuthorizationEndpoint != "" && oc.TokenEndpoint != ""
}

func (s *Server) redirectURI() string { return s.PublicURL + oauth.CallbackPath }

// handleOAuthStart discovers the server's authorization server, (dynamically) registers a client, mints
// PKCE + state, and returns the authorization URL for the operator's browser to open. Admin-guarded.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("server")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errObj("server query param required"))
		return
	}
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errObj("no config store"))
		return
	}
	sv, err := s.Store.GetMCPServer(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errObj("unknown server: "+name))
		return
	}
	if sv.Transport != "http" {
		writeJSON(w, http.StatusBadRequest, errObj("oauth applies to http servers only"))
		return
	}
	// The operator's PROFILE (if any). It is data, not code — see serverOAuthConfig.
	var oc serverOAuthConfig
	if sv.OAuthConfig != "" {
		if jerr := json.Unmarshal([]byte(sv.OAuthConfig), &oc); jerr != nil {
			writeJSON(w, http.StatusBadRequest, errObj("oauth config is not valid JSON: "+jerr.Error()))
			return
		}
	}

	// DISCOVERY FIRST, PROFILE OVER IT. A spec-compliant server needs no profile at all. A profile that
	// names both endpoints describes a provider that publishes NO metadata, so there is nothing to
	// discover and we must not fail trying — skip straight to the profile.
	cfg := oauth.Config{Resource: sv.Target}
	if !oc.selfDescribing() {
		var derr error
		if cfg, derr = oauth.Discover(r.Context(), nil, sv.Target); derr != nil {
			writeJSON(w, http.StatusBadGateway, errObj("oauth discovery failed: "+derr.Error()))
			return
		}
	}
	cfg = oc.apply(cfg)

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		writeJSON(w, http.StatusBadRequest, errObj(
			"could not find this provider's OAuth endpoints — set authorization_endpoint and token_endpoint in the server's oauth config"))
		return
	}

	cfg, err = oauth.Register(r.Context(), nil, cfg, s.redirectURI(), "StoaGraph ("+name+")")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errObj(err.Error()))
		return
	}
	if cfg.ClientID == "" {
		writeJSON(w, http.StatusBadRequest, errObj("this provider has no dynamic registration — set client_id in the server's oauth config"))
		return
	}
	verifier, challenge := oauth.PKCE()
	state := oauth.NewState()
	s.stashPending(state, pendingOAuth{server: name, verifier: verifier, cfg: cfg, created: time.Now()})
	writeJSON(w, http.StatusOK, map[string]any{"authUrl": cfg.AuthCodeURL(s.redirectURI(), state, challenge)})
}

// handleOAuthCallback is the provider's redirect target. It is PUBLIC (the provider redirects the
// operator's browser here and cannot carry our bearer); the unguessable state — minted only by an
// admin-authenticated start — is what authenticates the completion. It exchanges the code for tokens,
// persists them gate-side, and returns a self-closing page.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		oauthResultPage(w, "Sign-in was declined", strings2(e, q.Get("error_description")))
		return
	}
	p, ok := s.takePending(q.Get("state"))
	if !ok {
		oauthResultPage(w, "Sign-in expired", "Unknown or expired request — start the sign-in again from the console.")
		return
	}
	tok, err := p.cfg.Exchange(r.Context(), nil, s.redirectURI(), q.Get("code"), p.verifier)
	if err != nil {
		oauthResultPage(w, "Sign-in failed", err.Error())
		return
	}
	if err := s.OAuth.Save(p.server, oauth.State{Config: p.cfg, Tokens: tok}); err != nil {
		oauthResultPage(w, "Sign-in failed", "could not persist tokens: "+err.Error())
		return
	}
	oauthResultPage(w, "Signed in to "+p.server, "You can close this window.")
}

// handleOAuthStatus reports whether a server has a usable token, and when it expires. Read-guarded.
func (s *Server) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.OAuth.Load(r.URL.Query().Get("server"))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authorized": false})
		return
	}
	out := map[string]any{"authorized": st.Authorized(), "hasRefresh": st.Tokens.RefreshToken != ""}
	if !st.Tokens.Expiry.IsZero() {
		out["expiresAt"] = st.Tokens.Expiry
	}
	writeJSON(w, http.StatusOK, out)
}

// --- in-flight sign-in bookkeeping (in-memory, self-pruning) ----------------------------------------

const oauthPendingTTL = 15 * time.Minute

func (s *Server) stashPending(state string, p pendingOAuth) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	if s.oauthPending == nil {
		s.oauthPending = map[string]pendingOAuth{}
	}
	for k, v := range s.oauthPending { // prune abandoned flows
		if time.Since(v.created) > oauthPendingTTL {
			delete(s.oauthPending, k)
		}
	}
	s.oauthPending[state] = p
}

func (s *Server) takePending(state string) (pendingOAuth, bool) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	p, ok := s.oauthPending[state]
	if ok {
		delete(s.oauthPending, state)
	}
	return p, ok
}

func strings2(a, b string) string {
	if b == "" {
		return a
	}
	return a + ": " + b
}

// oauthResultPage renders a minimal self-closing page for the popup. Both fields are escaped — the
// message can carry provider-supplied error text.
func oauthResultPage(w http.ResponseWriter, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>%s</title>`+
		`<body style="font:15px system-ui;background:#0b0d12;color:#e6e8ec;display:grid;place-items:center;height:100vh;margin:0">`+
		`<div style="text-align:center;max-width:28rem;padding:2rem">`+
		`<div style="font-size:1.15rem;font-weight:600;margin-bottom:.5rem">%s</div>`+
		`<div style="color:#9aa3b2">%s</div></div>`+
		`<script>setTimeout(function(){window.close()},1200)</script>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg))
}
