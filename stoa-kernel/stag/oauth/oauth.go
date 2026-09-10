// Package oauth implements the downstream OAuth 2.1 authorization-code flow (PKCE + RFC 7591 dynamic
// client registration + RFC 8414/9728 metadata discovery) that the gate uses to obtain and refresh
// access tokens for OAuth-protected MCP servers.
//
// The security model is unchanged: the GATE holds the tokens and injects them at the proxy->tool hop;
// the agent never sees them. A human operator runs the interactive sign-in by opening
// GET /api/oauth/start?server=<name> in a browser (admin-only; stag-serve builds the authorization URL
// and handles the callback); the enforcement proxy only READS the stored tokens and refreshes them at
// connect. Non-secret config and the tokens persist per server as one JSON file under a shared
// directory, so both processes can read the same state off the data volume.
package oauth

// file-kw: oauth downstream authorization-code pkce dcr discovery refresh token-store bearer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// callbackPath is where the provider redirects after sign-in; stag-serve serves it. The caller composes
// the full redirect_uri as <public-url> + CallbackPath.
const CallbackPath = "/api/oauth/callback"

// refreshSkew refreshes a little BEFORE expiry so an in-flight connect never races the deadline.
const refreshSkew = 60 * time.Second

// Config is the NON-secret discovery + client result (safe to show); ClientSecret is the one sensitive
// field (empty for public PKCE clients, which is the MCP default).
// kw: oauth config endpoints client discovery
type Config struct {
	Resource              string   `json:"resource"` // the MCP server audience (RFC 8707)
	Issuer                string   `json:"issuer,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint,omitempty"`
	ClientID              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	// TokenAuthMethod is how this provider wants the client authenticated at the token endpoint
	// (client_secret_basic | client_secret_post | none). It is PER-PROVIDER — taken from the server's
	// advertised token_endpoint_auth_methods_supported — and persisted so a later refresh, loaded from
	// disk in another process, authenticates the same way the sign-in did.
	TokenAuthMethod string `json:"token_auth_method,omitempty"`

	// AuthorizeParams and TokenParams are the ESCAPE HATCH that makes this work for providers we have
	// never heard of, WITHOUT writing code for each one. Plenty of real providers need a non-standard
	// parameter and simply fail (often silently) without it:
	//
	//   Google  authorize: access_type=offline, prompt=consent   <- without these you get NO refresh
	//                                                               token and are logged out in an hour
	//   Auth0   authorize + token: audience=<api>                <- without it the token is unusable
	//   Slack   authorize: user_scope=<scopes>
	//
	// An operator declares these once, per server, as data. No adapter, no release.
	AuthorizeParams map[string]string `json:"authorize_params,omitempty"`
	TokenParams     map[string]string `json:"token_params,omitempty"`
}

// Tokens is the sensitive half: what actually authorizes downstream calls.
// kw: oauth tokens access refresh expiry
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// State is the full persisted per-server record.
// kw: oauth state config tokens persisted
type State struct {
	Config Config `json:"config"`
	Tokens Tokens `json:"tokens"`
}

// Authorized reports whether a usable access token is on file.
func (s State) Authorized() bool { return s.Tokens.AccessToken != "" }

// ---- file-backed store (data/oauth/<server>.json, 0600) --------------------------------------------

// Store persists one State per server as JSON under Dir. Both stag-serve (writes on callback) and
// stag-proxy (refreshes at connect) point at the same Dir on the shared data volume.
// kw: oauth store dir load save file
type Store struct{ Dir string }

func (s Store) path(server string) string { return filepath.Join(s.Dir, safeName(server)+".json") }

// Load reads a server's oauth state; a missing file is reported so callers can say "not authorized".
func (s Store) Load(server string) (State, error) {
	b, err := os.ReadFile(s.path(server))
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("oauth: corrupt state for %q: %w", server, err)
	}
	return st, nil
}

// Save writes a server's state atomically (temp + rename), 0600, creating Dir 0700 on first use.
// The temp file gets a UNIQUE name: a fixed one (<server>.json.tmp) makes concurrent saves clobber each
// other — two writers race on the same path and one's rename finds nothing there.
func (s Store) Save(server string, st State) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, safeName(server)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename succeeds
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(server))
}

// Bearer returns a fresh access token for server, refreshing if it is within refreshSkew of expiry.
// It is the connect-time resolver: the proxy maps an oauth scheme to a bearer credential through this.
// A missing/empty state yields an error (fail closed — no token, no downstream call).
// kw: oauth bearer resolve refresh connect
func (s Store) Bearer(ctx context.Context, hc *http.Client, server string) (string, error) {
	st, err := s.Load(server)
	if err != nil {
		return "", fmt.Errorf("oauth: %q not authorized (run sign-in): %w", server, err)
	}
	if !st.Authorized() {
		return "", fmt.Errorf("oauth: %q has no access token (run sign-in)", server)
	}
	if !stale(st) {
		return st.Tokens.AccessToken, nil // still good: no lock, no refresh
	}

	// REFRESH UNDER A CROSS-PROCESS LOCK. Providers rotate: a refresh token is single-use, and spending
	// it twice returns invalid_grant. stag-proxy (connect) and stag-serve (discovery) share this file, so
	// without the lock they can both spend the SAME token — one wins, the other fails, and a revoked
	// token can get persisted, locking the operator out of a server they authorized.
	//
	// Re-reading INSIDE the lock is the other half: by the time we get it, the winner may already have
	// refreshed and rotated. We must use their new token, not spend the dead one we read before waiting.
	var access string
	lerr := s.withLock(server, func() error {
		cur, err := s.Load(server)
		if err != nil {
			return err
		}
		if !stale(cur) { // another process refreshed while we waited — take its token, do not refresh again
			access = cur.Tokens.AccessToken
			return nil
		}
		if cur.Tokens.RefreshToken == "" {
			return fmt.Errorf("oauth: %q token expired and no refresh token (re-run sign-in)", server)
		}
		nt, rerr := cur.Config.Refresh(ctx, hc, cur.Tokens.RefreshToken)
		if rerr != nil {
			return fmt.Errorf("oauth: refresh for %q failed: %w", server, rerr)
		}
		if nt.RefreshToken == "" { // provider did not rotate: keep the existing one
			nt.RefreshToken = cur.Tokens.RefreshToken
		}
		cur.Tokens = nt
		if serr := s.Save(server, cur); serr != nil {
			return serr
		}
		access = nt.AccessToken
		return nil
	})
	if lerr != nil {
		return "", lerr
	}
	return access, nil
}

// stale reports whether the access token is at or near expiry (a zero expiry never expires).
func stale(st State) bool {
	return !st.Tokens.Expiry.IsZero() && time.Until(st.Tokens.Expiry) <= refreshSkew
}

// ---- discovery (RFC 9728 protected-resource -> RFC 8414 authorization-server) ----------------------

// Discover resolves the authorization + token (+ registration) endpoints for an MCP server URL. It
// tries the protected-resource metadata first (which names the authorization server), then the AS
// metadata; if neither is served it falls back to the MCP origin's well-known AS document, then to
// conventional /authorize + /token paths. Robust to the common case where a server serves only some of
// these documents. The returned Config has NO client yet — call Register (or set a pre-registered ID).
// kw: oauth discover metadata protected-resource authorization-server well-known
func Discover(ctx context.Context, hc *http.Client, mcpURL string) (Config, error) {
	hc = clientOr(hc)
	u, err := url.Parse(mcpURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, fmt.Errorf("oauth: invalid server URL %q", mcpURL)
	}
	origin := u.Scheme + "://" + u.Host
	cfg := Config{Resource: mcpURL}

	// 1) protected-resource metadata -> the authorization server issuer(s).
	//
	// RFC 9728 inserts the well-known segment BEFORE the resource path, so a resource at /mcp is
	// described at /.well-known/oauth-protected-resource/mcp — NOT at the bare origin. GitHub serves
	// only the path-scoped form (the bare one 404s). Best of all, the server's own 401 carries a
	// `WWW-Authenticate: ... resource_metadata="<url>"` hint naming the exact document, so ask it first.
	var prm struct {
		AuthorizationServers []string `json:"authorization_servers"`
		Resource             string   `json:"resource"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	for _, cand := range prmCandidates(ctx, hc, mcpURL, origin, u.Path) {
		if getJSON(ctx, hc, cand, &prm) == nil && len(prm.AuthorizationServers) > 0 {
			break
		}
	}
	issuer := origin
	if prm.Resource != "" {
		cfg.Resource = prm.Resource
	}
	if len(prm.AuthorizationServers) > 0 {
		issuer = strings.TrimRight(prm.AuthorizationServers[0], "/")
	}
	// Default the requested scopes to what the resource says it supports; without a scope the token a
	// provider mints can be useless. The operator can narrow this in the server's oauth config.
	if len(prm.ScopesSupported) > 0 {
		cfg.Scopes = prm.ScopesSupported
	}

	// 2) authorization-server metadata. RFC 8414 path-scopes too: an issuer WITH a path
	// (https://github.com/login/oauth) is described at
	// https://github.com/.well-known/oauth-authorization-server/login/oauth.
	for _, cand := range asCandidates(issuer) {
		var asm struct {
			Issuer                string   `json:"issuer"`
			AuthorizationEndpoint string   `json:"authorization_endpoint"`
			TokenEndpoint         string   `json:"token_endpoint"`
			RegistrationEndpoint  string   `json:"registration_endpoint"`
			TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
		}
		if getJSON(ctx, hc, cand, &asm) == nil && asm.TokenEndpoint != "" {
			cfg.Issuer = firstNonEmpty(asm.Issuer, issuer)
			cfg.AuthorizationEndpoint = asm.AuthorizationEndpoint
			cfg.TokenEndpoint = asm.TokenEndpoint
			cfg.RegistrationEndpoint = asm.RegistrationEndpoint
			// Which client-auth method this provider takes is ITS choice, not ours. Prefer Basic when it
			// is on offer: the RFC makes Basic mandatory for servers and leaves the body form optional.
			cfg.TokenAuthMethod = pickTokenAuth(asm.TokenAuthMethods)
			return cfg, nil
		}
	}

	// 3) last-resort conventional endpoints on the issuer
	cfg.Issuer = issuer
	cfg.AuthorizationEndpoint = issuer + "/authorize"
	cfg.TokenEndpoint = issuer + "/token"
	return cfg, nil
}

// prmCandidates lists protected-resource-metadata URLs to try, best first: the one the server itself
// names in its 401 challenge, then the RFC 9728 path-scoped form, then the bare origin.
func prmCandidates(ctx context.Context, hc *http.Client, mcpURL, origin, path string) []string {
	var out []string
	if hint := challengeMetadataURL(ctx, hc, mcpURL); hint != "" {
		out = append(out, hint)
	}
	if p := strings.Trim(path, "/"); p != "" {
		out = append(out, origin+"/.well-known/oauth-protected-resource/"+p)
	}
	return append(out, origin+"/.well-known/oauth-protected-resource")
}

// asCandidates lists authorization-server-metadata URLs for an issuer that may carry a path.
func asCandidates(issuer string) []string {
	var out []string
	if u, err := url.Parse(issuer); err == nil && u.Host != "" {
		if p := strings.Trim(u.Path, "/"); p != "" {
			iOrigin := u.Scheme + "://" + u.Host
			out = append(out,
				iOrigin+"/.well-known/oauth-authorization-server/"+p,
				iOrigin+"/.well-known/openid-configuration/"+p,
			)
		}
	}
	return append(out,
		issuer+"/.well-known/oauth-authorization-server",
		issuer+"/.well-known/openid-configuration",
	)
}

// challengeMetadataURL reads the resource_metadata="..." hint from the server's 401 WWW-Authenticate
// challenge — the spec's most reliable pointer to its metadata document. Empty when absent.
func challengeMetadataURL(ctx context.Context, hc *http.Client, mcpURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpURL, nil)
	if err != nil {
		return ""
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	for _, h := range resp.Header.Values("WWW-Authenticate") {
		const key = `resource_metadata=`
		i := strings.Index(h, key)
		if i < 0 {
			continue
		}
		v := strings.TrimSpace(h[i+len(key):])
		v = strings.TrimPrefix(v, `"`)
		if j := strings.IndexAny(v, `",`); j >= 0 {
			v = v[:j]
		}
		if strings.HasPrefix(v, "http") {
			return strings.TrimRight(v, "/")
		}
	}
	return ""
}

// Register performs RFC 7591 dynamic client registration when the AS advertises an endpoint, yielding a
// client_id (and client_secret for confidential clients). MCP clients are typically PUBLIC and use PKCE,
// so we request token_endpoint_auth_method "none". When there is no registration endpoint, the caller
// must have supplied a pre-registered ClientID.
// kw: oauth register dcr dynamic client
func Register(ctx context.Context, hc *http.Client, cfg Config, redirectURI, clientName string) (Config, error) {
	if cfg.ClientID != "" || cfg.RegistrationEndpoint == "" {
		return cfg, nil // pre-registered, or DCR unsupported (caller validates ClientID presence)
	}
	req := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                clientName,
	}
	if len(cfg.Scopes) > 0 {
		req["scope"] = strings.Join(cfg.Scopes, " ")
	}
	body, _ := json.Marshal(req)
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := postJSON(ctx, clientOr(hc), cfg.RegistrationEndpoint, body, &out); err != nil {
		return cfg, fmt.Errorf("oauth: dynamic client registration failed: %w", err)
	}
	if out.ClientID == "" {
		return cfg, fmt.Errorf("oauth: registration returned no client_id")
	}
	cfg.ClientID, cfg.ClientSecret = out.ClientID, out.ClientSecret
	return cfg, nil
}

// PKCE returns a fresh (verifier, S256 challenge) pair.
// kw: oauth pkce verifier challenge s256
func PKCE() (verifier, challenge string) {
	verifier = randB64(64)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// NewState returns a random opaque state token (CSRF + pending-flow key).
func NewState() string { return randB64(32) }

// AuthCodeURL builds the authorization-endpoint URL for the browser to open, carrying PKCE + the
// resource indicator (RFC 8707) so the AS mints a token audience-bound to this MCP server.
// kw: oauth auth-code url authorize pkce resource
func (c Config) AuthCodeURL(redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if c.Resource != "" {
		q.Set("resource", c.Resource)
	}
	if len(c.Scopes) > 0 {
		q.Set("scope", strings.Join(c.Scopes, " "))
	}
	for k, v := range c.AuthorizeParams { // provider-specific: audience, access_type, prompt, user_scope…
		q.Set(k, v)
	}
	sep := "?"
	if strings.Contains(c.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return c.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange trades an authorization code (+ PKCE verifier) for tokens at the token endpoint.
// kw: oauth exchange authorization-code token
func (c Config) Exchange(ctx context.Context, hc *http.Client, redirectURI, code, verifier string) (Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("code_verifier", verifier)
	if c.Resource != "" {
		form.Set("resource", c.Resource)
	}
	return c.tokenRequest(ctx, hc, form)
}

// Refresh trades a refresh token for a new access token.
// kw: oauth refresh token grant
func (c Config) Refresh(ctx context.Context, hc *http.Client, refreshToken string) (Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.ClientID)
	if c.Resource != "" {
		form.Set("resource", c.Resource)
	}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	return c.tokenRequest(ctx, hc, form)
}

// Client authentication methods at the token endpoint (RFC 6749 §2.3). Which one a provider accepts is
// PER-PROVIDER and advertised in `token_endpoint_auth_methods_supported`.
const (
	AuthBasic = "client_secret_basic" // secret in an HTTP Basic header. The RFC says servers MUST support it.
	AuthPost  = "client_secret_post"  // secret in the form body. Optional per the RFC — but common.
	AuthNone  = "none"                // public client: no secret, PKCE only.
)

// tokenAuthOrder is the client-authentication methods to attempt, best first.
//
// A public client (no secret) sends none. Otherwise we honour what the server ADVERTISED, and keep the
// other method as a fallback: metadata is sometimes absent, stale, or simply wrong, and a provider that
// rejects our first attempt with invalid_client will accept the other. Guessing one and giving up is how
// you get an "OAuth works — except with Okta" bug.
func (c Config) tokenAuthOrder() []string {
	if c.ClientSecret == "" {
		return []string{AuthNone}
	}
	switch c.TokenAuthMethod {
	case AuthBasic:
		return []string{AuthBasic, AuthPost}
	case AuthPost:
		return []string{AuthPost, AuthBasic}
	default: // undeclared: try the body first (widely accepted), then Basic (the mandatory one)
		return []string{AuthPost, AuthBasic}
	}
}

// tokenRequest posts to the token endpoint, retrying with the other client-auth method if the provider
// rejects our credentials. Any NON-auth failure (bad grant, expired code) returns immediately — retrying
// those would just replay a spent code.
func (c Config) tokenRequest(ctx context.Context, hc *http.Client, form url.Values) (Tokens, error) {
	var lastErr error
	for _, method := range c.tokenAuthOrder() {
		t, err := c.tokenRequestWith(ctx, hc, form, method)
		if err == nil {
			return t, nil
		}
		lastErr = err
		if !isClientAuthError(err) {
			return Tokens{}, err // not a credentials problem: do not retry
		}
	}
	return Tokens{}, lastErr
}

// clientAuthErr marks a token-endpoint rejection of our CLIENT CREDENTIALS (as opposed to the grant), so
// the caller knows the other auth method is worth trying.
type clientAuthErr struct{ err error }

func (e clientAuthErr) Error() string { return e.err.Error() }
func (e clientAuthErr) Unwrap() error { return e.err }

func isClientAuthError(err error) bool {
	var e clientAuthErr
	return errors.As(err, &e)
}

func (c Config) tokenRequestWith(ctx context.Context, hc *http.Client, form url.Values, method string) (Tokens, error) {
	f := url.Values{}
	for k, v := range form { // copy: a retry must not inherit the previous attempt's credentials
		f[k] = v
	}
	for k, v := range c.TokenParams { // provider-specific (e.g. Auth0's audience)
		f.Set(k, v)
	}
	if method == AuthPost && c.ClientSecret != "" {
		f.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, strings.NewReader(f.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	if method == AuthBasic && c.ClientSecret != "" {
		// RFC 6749 §2.3.1: the credentials are form-urlencoded before base64, and travel in the header.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := clientOr(hc).Do(req)
	if err != nil {
		return Tokens{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		e := fmt.Errorf("oauth: token endpoint %d (%s): %s", resp.StatusCode, method, strings.TrimSpace(string(b)))
		// 401, or an explicit invalid_client, means it refused our CREDENTIALS — the other method may work.
		if resp.StatusCode == http.StatusUnauthorized || bytes.Contains(b, []byte("invalid_client")) {
			return Tokens{}, clientAuthErr{e}
		}
		return Tokens{}, e
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Tokens{}, fmt.Errorf("oauth: bad token response: %w", err)
	}
	if raw.AccessToken == "" {
		return Tokens{}, fmt.Errorf("oauth: token response had no access_token")
	}
	t := Tokens{AccessToken: raw.AccessToken, RefreshToken: raw.RefreshToken, TokenType: raw.TokenType}
	if raw.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return t, nil
}

// ---- helpers ---------------------------------------------------------------------------------------

func clientOr(hc *http.Client) *http.Client {
	if hc != nil {
		return hc
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: %d", u, resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return json.Unmarshal(b, out)
}

func postJSON(ctx context.Context, hc *http.Client, u string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: %d: %s", u, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// safeName constrains a server name to a filesystem-safe basename (it becomes a filename).
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// pickTokenAuth chooses a client-authentication method from what the server advertises. Basic first (the
// RFC-mandatory one), then the body form. An empty result means "undeclared" — tokenAuthOrder then tries
// both rather than guessing.
// kw: token endpoint auth method basic post negotiate
func pickTokenAuth(supported []string) string {
	has := func(m string) bool {
		for _, s := range supported {
			if s == m {
				return true
			}
		}
		return false
	}
	switch {
	case has(AuthBasic):
		return AuthBasic
	case has(AuthPost):
		return AuthPost
	default:
		return ""
	}
}
