package oauth_test

// Integration test against a REAL OAuth 2.0 / OIDC identity provider, not a mock.
//
// Mocks prove we call what we think we call; they cannot prove we interoperate. Every OAuth bug found in
// this package so far came from a real provider disagreeing with our assumptions (GitHub serves its
// metadata at the RFC-9728 PATH-SCOPED URL, and has no dynamic registration at all). So this drives the
// whole flow — discovery, dynamic client registration, PKCE, the authorization-code redirect, the token
// exchange, and refresh-token ROTATION — against @rustmcp/oauth2-test-server, an in-memory OIDC server
// built for exactly this.
//
// Its /authorize auto-approves a hardcoded test user, so the flow runs headlessly: no browser, no human.
//
//	npm i -g @rustmcp/oauth2-test-server && oauth2-test-server     # http://localhost:8090
//	go test ./stag/oauth/ -run TestAgainstRealIdP -v
//
// It SKIPS when the IdP is not running, so `go test ./...` stays green without it.

// kw-test: oauth integration real idp dcr pkce authorization-code exchange refresh rotation loopback

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
)

// idpBase is where the test IdP listens. Override with STOAGRAPH_IDP_URL.
func idpBase() string {
	if v := os.Getenv("STOAGRAPH_IDP_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8090"
}

// liveIdP skips the test unless the IdP answers its discovery document.
func liveIdP(t *testing.T) string {
	t.Helper()
	base := idpBase()
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("no OAuth test IdP at %s (npm i -g @rustmcp/oauth2-test-server && oauth2-test-server): %v", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Skipf("IdP at %s returned %d for its discovery document", base, resp.StatusCode)
	}
	return base
}

func TestAgainstRealIdP(t *testing.T) {
	base := liveIdP(t)
	ctx := context.Background()
	redirect := "http://localhost:8080" + oauth.CallbackPath

	// 1. DISCOVERY. The IdP is not an MCP resource, so the protected-resource probe misses and we fall
	//    through to its OIDC document — exercising the same fallback ladder a bare AS would hit.
	cfg, err := oauth.Discover(ctx, nil, base)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if cfg.TokenEndpoint == "" || cfg.AuthorizationEndpoint == "" {
		t.Fatalf("discovery found no endpoints: %+v", cfg)
	}
	if cfg.RegistrationEndpoint == "" {
		t.Fatalf("this IdP advertises dynamic registration; discovery missed it: %+v", cfg)
	}
	t.Logf("discovered: authorize=%s token=%s register=%s", cfg.AuthorizationEndpoint, cfg.TokenEndpoint, cfg.RegistrationEndpoint)

	// 2. DYNAMIC CLIENT REGISTRATION (RFC 7591). The gate registers ITSELF — no operator-provided
	//    client_id — which is the zero-config path MCP servers are supposed to support.
	cfg, err = oauth.Register(ctx, nil, cfg, redirect, "stoagraph-test")
	if err != nil {
		t.Fatalf("dynamic client registration: %v", err)
	}
	if cfg.ClientID == "" {
		t.Fatal("DCR returned no client_id")
	}
	t.Logf("registered client_id=%s (secret set: %t)", cfg.ClientID, cfg.ClientSecret != "")

	// 3. AUTHORIZATION CODE + PKCE. The IdP auto-approves its test user and 302s back to our loopback
	//    redirect_uri with the code — so we can drive the browser leg headlessly.
	verifier, challenge := oauth.PKCE()
	state := oauth.NewState()
	authURL := cfg.AuthCodeURL(redirect, state, challenge)

	noRedirect := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize should 302 back to the redirect_uri, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect Location: %v", err)
	}
	if e := loc.Query().Get("error"); e != "" {
		t.Fatalf("authorize refused: %s (%s)", e, loc.Query().Get("error_description"))
	}
	// the state we sent must come back untouched — this is the CSRF binding, not a formality
	if got := loc.Query().Get("state"); got != state {
		t.Fatalf("state not echoed: sent %q, got %q", state, got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in redirect: %s", loc)
	}

	// 4. TOKEN EXCHANGE (with the PKCE verifier).
	tok, err := cfg.Exchange(ctx, nil, redirect, code, verifier)
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("exchange returned no access token")
	}
	if tok.RefreshToken == "" {
		t.Fatal("exchange returned no refresh token — refresh rotation is untestable without one")
	}
	if tok.Expiry.IsZero() || time.Until(tok.Expiry) <= 0 {
		t.Fatalf("access token expiry is not in the future: %v", tok.Expiry)
	}
	t.Logf("exchanged: access=%s… refresh=%s… expires in %s",
		trunc(tok.AccessToken), trunc(tok.RefreshToken), time.Until(tok.Expiry).Round(time.Second))

	// 5. REFRESH. A wrong PKCE verifier or a mis-encoded form dies here, not earlier.
	rt, err := cfg.Refresh(ctx, nil, tok.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rt.AccessToken == "" {
		t.Fatal("refresh returned no access token")
	}
	if rt.AccessToken == tok.AccessToken {
		t.Fatal("refresh returned the SAME access token — nothing was actually refreshed")
	}
	t.Logf("refreshed: new access=%s… (rotated refresh: %t)", trunc(rt.AccessToken), rt.RefreshToken != "" && rt.RefreshToken != tok.RefreshToken)

	// 6. THE GATE'S RESOLVER. This is the path the proxy takes at connect: load the stored state, notice
	//    the token is at/near expiry, refresh it, persist, and hand back a usable bearer.
	//
	//    ROTATION IS THE TRAP. This provider issues a NEW refresh token on every refresh and REVOKES the
	//    old one (single-use). So we must seed with the refresh token from step 5 — `tok.RefreshToken` was
	//    already spent there and is now dead (it returns invalid_grant). And the gate must PERSIST each
	//    rotated token: keep the old one and the next refresh fails, locking the operator out until they
	//    sign in again. That is precisely what this step asserts.
	st := oauth.Store{Dir: t.TempDir()}
	expired := oauth.State{Config: cfg, Tokens: oauth.Tokens{
		AccessToken:  rt.AccessToken,
		RefreshToken: rt.RefreshToken,              // the CURRENT one; step 5 rotated the original away
		Expiry:       time.Now().Add(-time.Second), // force the refresh path
	}}
	if err := st.Save("idp-test", expired); err != nil {
		t.Fatalf("save: %v", err)
	}
	bearer, err := st.Bearer(ctx, nil, "idp-test")
	if err != nil {
		t.Fatalf("Store.Bearer must refresh an expired token: %v", err)
	}
	if bearer == "" || bearer == rt.AccessToken {
		t.Fatalf("Bearer did not refresh: got %q", trunc(bearer))
	}
	after, err := st.Load("idp-test")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Tokens.AccessToken != bearer {
		t.Fatal("the refreshed access token was not persisted")
	}
	if after.Tokens.RefreshToken == "" {
		t.Fatal("the refresh token was dropped on refresh — the next refresh would fail and lock us out")
	}
	t.Logf("resolver refreshed + persisted; refresh token %s",
		map[bool]string{true: "ROTATED and stored", false: "reused"}[after.Tokens.RefreshToken != rt.RefreshToken])

	// The rotated refresh token must actually WORK. Persisting a dead token would look fine on disk and
	// fail on the next connect.
	if _, err := cfg.Refresh(ctx, nil, after.Tokens.RefreshToken); err != nil {
		t.Fatalf("the persisted refresh token is not usable — the next connect would lock us out: %v", err)
	}
}

func trunc(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
