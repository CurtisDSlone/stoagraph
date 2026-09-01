package serve_test

// End-to-end test of the gate's OAuth HTTP endpoints against a REAL identity provider.
//
// oauth_test.go in stag/oauth proves the protocol library interoperates. This proves the SERVER WIRING
// around it: /api/oauth/start really discovers + dynamically registers a client and mints a PKCE
// challenge; the provider's redirect really lands on /api/oauth/callback; the callback really exchanges
// the code and persists the tokens gate-side; and /api/oauth/status really reports authorized. That is
// the exact sequence the console's "Sign in" button drives — minus the browser, because this IdP's
// /authorize auto-approves a test user.
//
//	npm i -g @rustmcp/oauth2-test-server && oauth2-test-server     # http://localhost:8090
//	go test ./stag/serve/ -run TestOAuthSignInAgainstRealIdP -v
//
// SKIPS when the IdP is not running, so `go test ./...` stays green without it.

// kw-test: oauth endpoints integration start callback status real idp dcr pkce sign-in

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

func idpURL() string {
	if v := os.Getenv("STOAGRAPH_IDP_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8090"
}

func requireIdP(t *testing.T) string {
	t.Helper()
	base := idpURL()
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("no OAuth test IdP at %s (npm i -g @rustmcp/oauth2-test-server && oauth2-test-server): %v", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Skipf("IdP at %s returned %d", base, resp.StatusCode)
	}
	return base
}

func TestOAuthSignInAgainstRealIdP(t *testing.T) {
	idp := requireIdP(t)
	ctx := context.Background()

	cfgStore, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cfgStore.Close() })

	oauthDir := t.TempDir()
	srv := &serve.Server{
		Gate:    proxy.Gate{Routes: proxy.Router{}},
		Recipes: recipestore.Store{Dir: t.TempDir()},
		Store:   cfgStore,
		Auth:    &auth.Authenticator{Disabled: true},
		OAuth:   oauth.Store{Dir: oauthDir},
	}

	// Stand the gate up on a real socket: the redirect_uri must be an address the IdP can actually send
	// a browser back to, and it is registered with the provider during DCR.
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.PublicURL = ts.URL // redirect_uri = <this>/api/oauth/callback

	// The operator registers an oauth-scheme server pointing at the IdP.
	if err := cfgStore.PutMCPServer(ctx, store.MCPServer{
		Name: "idp", Transport: "http", Target: idp, Enabled: true, AuthScheme: "oauth",
	}); err != nil {
		t.Fatal(err)
	}

	// not signed in yet
	if authorized(t, ts.URL, "idp") {
		t.Fatal("a freshly registered server must not be authorized")
	}

	// 1. START — the console's "Sign in" click. Discovers the AS, dynamically registers a client, mints
	//    PKCE + state, and returns the URL the browser should open.
	resp, err := http.Post(ts.URL+"/api/oauth/start?server=idp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io_ReadAll(resp)
		t.Fatalf("oauth start: %d: %s", resp.StatusCode, b)
	}
	var start struct {
		AuthURL string `json:"authUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil {
		t.Fatal(err)
	}
	if start.AuthURL == "" {
		t.Fatal("start returned no authUrl")
	}
	for _, want := range []string{"code_challenge_method=S256", "response_type=code", "state="} {
		if !strings.Contains(start.AuthURL, want) {
			t.Fatalf("authUrl missing %q: %s", want, start.AuthURL)
		}
	}

	// 2. THE BROWSER LEG. The IdP auto-approves and 302s to our redirect_uri with the code. Following
	//    that redirect lands on the gate's real /api/oauth/callback, which exchanges and persists.
	browser := &http.Client{Timeout: 10 * time.Second} // follows redirects, like a browser
	ar, err := browser.Get(start.AuthURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer ar.Body.Close()
	if ar.StatusCode != 200 {
		t.Fatalf("the callback should render a page, got %d", ar.StatusCode)
	}
	if u := ar.Request.URL; !strings.Contains(u.Path, oauth.CallbackPath) {
		t.Fatalf("the redirect chain should end at our callback, ended at %s", u)
	}
	body, _ := io_ReadAll(ar)
	if strings.Contains(strings.ToLower(body), "sign-in failed") || strings.Contains(strings.ToLower(body), "expired") {
		t.Fatalf("callback reported failure: %s", body)
	}

	// 3. STATUS — the console polls this until it flips. The gate now holds the tokens.
	if !authorized(t, ts.URL, "idp") {
		t.Fatal("after the callback the gate must hold a usable token")
	}

	// 4. AND THE TOKENS ARE REALLY THERE, gate-side, never in the browser: the resolver the proxy uses at
	//    connect must hand back a bearer for this server.
	tok, err := (oauth.Store{Dir: oauthDir}).Bearer(ctx, nil, "idp")
	if err != nil {
		t.Fatalf("the proxy's connect-time resolver must produce a bearer: %v", err)
	}
	if tok == "" {
		t.Fatal("empty bearer")
	}

	// the persisted state must carry a refresh token, or the first expiry locks us out
	st, err := (oauth.Store{Dir: oauthDir}).Load("idp")
	if err != nil {
		t.Fatal(err)
	}
	if st.Tokens.RefreshToken == "" {
		t.Fatal("no refresh token persisted — the session dies at first expiry")
	}
	if st.Config.ClientID == "" {
		t.Fatal("no client_id persisted — a refresh would have nothing to authenticate with")
	}
	t.Logf("signed in: client_id=%s, bearer=%s…, refresh stored", st.Config.ClientID, tok[:min(12, len(tok))])
}

func authorized(t *testing.T, base, server string) bool {
	t.Helper()
	resp, err := http.Get(base + "/api/oauth/status?server=" + url.QueryEscape(server))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s struct {
		Authorized bool `json:"authorized"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&s)
	return s.Authorized
}

func io_ReadAll(r *http.Response) (string, error) {
	b := make([]byte, 4096)
	n, _ := r.Body.Read(b)
	return string(b[:n]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
