package serve_test

// kw-test: provider profiles are DATA — extra authorize/token params, and endpoints for a server that
// publishes no metadata at all. Adding a provider must never require code.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// gateWith stands the console API up over a config store, and registers one oauth server with `profile`
// as its oauth_config. Returns the gate's base URL.
func gateWith(t *testing.T, target, profile string) string {
	t.Helper()
	cs, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	srv := &serve.Server{
		Gate:    proxy.Gate{Routes: proxy.Router{}},
		Recipes: recipestore.Store{Dir: t.TempDir()},
		Store:   cs,
		Auth:    &auth.Authenticator{Disabled: true},
		OAuth:   oauth.Store{Dir: t.TempDir()},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.PublicURL = ts.URL

	if err := cs.PutMCPServer(context.Background(), store.MCPServer{
		Name: "svc", Transport: "http", Target: target, Enabled: true,
		AuthScheme: "oauth", OAuthConfig: profile,
	}); err != nil {
		t.Fatal(err)
	}
	return ts.URL
}

// startAuthURL calls /api/oauth/start and returns the authorization URL it minted.
func startAuthURL(t *testing.T, gate string) *url.URL {
	t.Helper()
	resp, err := http.Post(gate+"/api/oauth/start?server=svc", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AuthURL string `json:"authUrl"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		t.Fatalf("oauth start: %d: %s", resp.StatusCode, out.Error)
	}
	u, err := url.Parse(out.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestProfileAuthorizeParams is the GOOGLE case, and the reason authorize_params exists.
//
// Without access_type=offline, Google completes the sign-in and issues NO refresh token. Nothing errors.
// The operator is silently logged out an hour later with no way back. A profile must be able to add that
// parameter without anyone writing a Google adapter.
func TestProfileAuthorizeParams(t *testing.T) {
	as := metadataAS(t, nil)
	defer as.Close()

	gate := gateWith(t, as.URL, `{
		"client_id": "goog-client",
		"scopes": ["openid","email"],
		"authorize_params": {"access_type":"offline","prompt":"consent"}
	}`)

	u := startAuthURL(t, gate)
	q := u.Query()
	if q.Get("access_type") != "offline" {
		t.Fatalf("access_type missing from the authorize URL — Google would issue no refresh token: %s", u)
	}
	if q.Get("prompt") != "consent" {
		t.Fatalf("prompt missing: %s", u)
	}
	// and the standard params must survive the overlay
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "goog-client" {
		t.Fatalf("profile params must ADD to the standard ones, not replace them: %s", u)
	}
}

// TestProfileSelfDescribingSkipsDiscovery is the BESPOKE case: a provider that publishes no metadata at
// all. Naming both endpoints must skip discovery entirely — not probe, guess /authorize, and fail.
func TestProfileSelfDescribingSkipsDiscovery(t *testing.T) {
	// a target that serves NOTHING: any discovery probe 404s
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer silent.Close()

	gate := gateWith(t, silent.URL, `{
		"authorization_endpoint": "https://vendor.example.com/oauth/authorize",
		"token_endpoint": "https://vendor.example.com/oauth/token",
		"client_id": "vendor-client",
		"token_auth_method": "client_secret_basic"
	}`)

	u := startAuthURL(t, gate)
	if u.Host != "vendor.example.com" || u.Path != "/oauth/authorize" {
		t.Fatalf("must use the profile's endpoint verbatim, got %s", u)
	}
	if u.Query().Get("client_id") != "vendor-client" {
		t.Fatalf("client_id not applied: %s", u)
	}
}

// TestProfileMissingEndpointsIsActionable — a provider with no metadata AND no profile must say what to
// do, not fail with a confusing connect error against a guessed URL.
func TestProfileMissingEndpointsIsActionable(t *testing.T) {
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer silent.Close()

	gate := gateWith(t, silent.URL, "")
	resp, err := http.Post(gate+"/api/oauth/start?server=svc", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	// Discovery falls back to conventional endpoints, so we get as far as "no client_id" — either way the
	// operator must be told which knob to turn.
	if resp.StatusCode == 200 {
		t.Fatal("a provider with no metadata and no profile must not silently proceed")
	}
	if !strings.Contains(out.Error, "client_id") && !strings.Contains(out.Error, "endpoint") {
		t.Fatalf("the error must name the field to set, got: %q", out.Error)
	}
}

// metadataAS is a minimal authorization server that publishes standard metadata.
func metadataAS(t *testing.T, authMethods []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
		}
		if authMethods != nil {
			doc["token_endpoint_auth_methods_supported"] = authMethods
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}
