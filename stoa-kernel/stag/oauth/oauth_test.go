package oauth_test

// kw-test: oauth discovery dcr pkce exchange refresh store bearer against a mock authorization server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
)

// mockAS stands up an authorization server that serves the discovery documents, dynamic registration,
// and the token endpoint (both authorization_code and refresh_token grants).
func mockAS(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"authorization_servers": []string{base}, "resource": base + "/mcp"})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"registration_endpoint":  base + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		writeJSON(w, map[string]any{"client_id": "client-123"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code_verifier") == "" || r.Form.Get("code") == "" {
				w.WriteHeader(400)
				return
			}
			writeJSON(w, map[string]any{"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			if r.Form.Get("refresh_token") == "" {
				w.WriteHeader(400)
				return
			}
			writeJSON(w, map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(400)
		}
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestFullFlow(t *testing.T) {
	srv := mockAS(t)
	defer srv.Close()
	ctx := context.Background()
	hc := srv.Client()
	redirect := "http://localhost:8080" + oauth.CallbackPath

	cfg, err := oauth.Discover(ctx, hc, srv.URL+"/mcp")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if cfg.TokenEndpoint != srv.URL+"/token" || cfg.AuthorizationEndpoint != srv.URL+"/authorize" {
		t.Fatalf("endpoints wrong: %+v", cfg)
	}
	if cfg.RegistrationEndpoint != srv.URL+"/register" {
		t.Fatalf("registration endpoint wrong: %q", cfg.RegistrationEndpoint)
	}
	if cfg.Resource != srv.URL+"/mcp" {
		t.Fatalf("resource wrong: %q", cfg.Resource)
	}

	cfg, err = oauth.Register(ctx, hc, cfg, redirect, "stoagraph")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if cfg.ClientID != "client-123" {
		t.Fatalf("client id: %q", cfg.ClientID)
	}

	verifier, challenge := oauth.PKCE()
	state := oauth.NewState()
	au := cfg.AuthCodeURL(redirect, state, challenge)
	for _, want := range []string{"response_type=code", "code_challenge_method=S256", "state=" + state, "client_id=client-123", "resource="} {
		if !strings.Contains(au, want) {
			t.Fatalf("auth url missing %q: %s", want, au)
		}
	}

	tok, err := cfg.Exchange(ctx, hc, redirect, "the-code", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" {
		t.Fatalf("tokens: %+v", tok)
	}
	if tok.Expiry.IsZero() || time.Until(tok.Expiry) <= 0 {
		t.Fatalf("expiry not in the future: %v", tok.Expiry)
	}

	rt, err := cfg.Refresh(ctx, hc, tok.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rt.AccessToken != "at-2" {
		t.Fatalf("refresh access: %q", rt.AccessToken)
	}
}

func TestStoreRoundTripAndBearerRefresh(t *testing.T) {
	srv := mockAS(t)
	defer srv.Close()
	ctx := context.Background()
	hc := srv.Client()

	st := oauth.Store{Dir: t.TempDir()}
	// seed a near-expired token so Bearer must refresh (rt-1 -> at-2)
	seed := oauth.State{
		Config: oauth.Config{TokenEndpoint: srv.URL + "/token", ClientID: "client-123", Resource: srv.URL + "/mcp"},
		Tokens: oauth.Tokens{AccessToken: "at-1", RefreshToken: "rt-1", Expiry: time.Now().Add(-1 * time.Second)},
	}
	if err := st.Save("alpha vantage", seed); err != nil { // name has a space: safeName must handle it
		t.Fatalf("save: %v", err)
	}
	got, err := st.Load("alpha vantage")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Tokens.AccessToken != "at-1" {
		t.Fatalf("round-trip: %+v", got)
	}

	tok, err := st.Bearer(ctx, hc, "alpha vantage")
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	if tok != "at-2" {
		t.Fatalf("bearer did not refresh: %q", tok)
	}
	// the refreshed token (and the preserved refresh token) must be persisted
	after, _ := st.Load("alpha vantage")
	if after.Tokens.AccessToken != "at-2" || after.Tokens.RefreshToken != "rt-1" {
		t.Fatalf("refresh not persisted / refresh token not preserved: %+v", after.Tokens)
	}
}

// TestDiscoverGitHubShape reproduces the real GitHub MCP server: the protected-resource metadata is
// served ONLY at the RFC 9728 path-scoped URL (/.well-known/oauth-protected-resource/mcp — the bare
// origin 404s), the 401 challenge names that document, the issuer carries a PATH (/login/oauth) so its
// RFC 8414 metadata is path-scoped too, and there is NO registration endpoint (no dynamic registration).
// Every one of those broke the first implementation.
func TestDiscoverGitHubShape(t *testing.T) {
	mux := http.NewServeMux()
	var base string

	// the MCP endpoint itself: 401 + a challenge naming the metadata document
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate",
			`Bearer error="invalid_request", resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	// bare protected-resource metadata: NOT served (like GitHub)
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	// path-scoped protected-resource metadata: the real one
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"resource":              base + "/mcp",
			"authorization_servers": []string{base + "/login/oauth"}, // issuer WITH a path
			"scopes_supported":      []string{"repo", "read:org"},
		})
	})
	// issuer-suffixed AS metadata: NOT served (like GitHub)
	mux.HandleFunc("/login/oauth/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	// path-scoped AS metadata (RFC 8414): the real one — and no registration_endpoint
	mux.HandleFunc("/.well-known/oauth-authorization-server/login/oauth", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                           base + "/login/oauth",
			"authorization_endpoint":           base + "/login/oauth/authorize",
			"token_endpoint":                   base + "/login/oauth/access_token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})

	srv := httptest.NewServer(mux)
	base = srv.URL
	defer srv.Close()

	cfg, err := oauth.Discover(context.Background(), srv.Client(), srv.URL+"/mcp")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if cfg.AuthorizationEndpoint != base+"/login/oauth/authorize" {
		t.Fatalf("authorization_endpoint not found via path-scoped metadata: %q", cfg.AuthorizationEndpoint)
	}
	if cfg.TokenEndpoint != base+"/login/oauth/access_token" {
		t.Fatalf("token_endpoint wrong: %q", cfg.TokenEndpoint)
	}
	if cfg.RegistrationEndpoint != "" {
		t.Fatalf("expected NO registration endpoint, got %q", cfg.RegistrationEndpoint)
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "repo" {
		t.Fatalf("scopes_supported not adopted: %v", cfg.Scopes)
	}
	if cfg.Resource != base+"/mcp" {
		t.Fatalf("resource wrong: %q", cfg.Resource)
	}

	// No DCR: Register must leave the client empty so the caller can demand a pre-registered client_id.
	got, rerr := oauth.Register(context.Background(), srv.Client(), cfg, "http://localhost:8080"+oauth.CallbackPath, "stoagraph")
	if rerr != nil {
		t.Fatalf("register should no-op without a registration endpoint, got: %v", rerr)
	}
	if got.ClientID != "" {
		t.Fatalf("expected no client_id without DCR, got %q", got.ClientID)
	}
}

func TestBearerUnauthorized(t *testing.T) {
	st := oauth.Store{Dir: t.TempDir()}
	if _, err := st.Bearer(context.Background(), nil, "never-signed-in"); err == nil {
		t.Fatal("expected error for a server with no stored token")
	}
}
