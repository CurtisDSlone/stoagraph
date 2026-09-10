package oauth_test

// kw-test: concurrent refresh + rotation — two gate processes must not spend the same single-use token

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
)

// freshTokens runs the real flow (discover -> DCR -> PKCE -> authorize -> exchange) and returns a live
// config plus a valid token pair. Each call mints a NEW client + code, so tests never share a token.
func freshTokens(t *testing.T, ctx context.Context) (oauth.Config, oauth.Tokens) {
	t.Helper()
	base := liveIdP(t)
	redirect := "http://localhost:8080" + oauth.CallbackPath

	cfg, err := oauth.Discover(ctx, nil, base)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	cfg, err = oauth.Register(ctx, nil, cfg, redirect, "stoagraph-race")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	verifier, challenge := oauth.PKCE()
	noRedirect := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Get(cfg.AuthCodeURL(redirect, oauth.NewState(), challenge))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from authorize: %s", loc)
	}
	tok, err := cfg.Exchange(ctx, nil, redirect, code, verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return cfg, tok
}

// TestConcurrentRefreshDoesNotLockOut is the production hazard that refresh-token ROTATION creates.
//
// The refresh token is SINGLE-USE: refreshing rotates it and revokes the old one. Two gate processes read
// the same data/oauth/<server>.json — stag-proxy refreshes at connect, stag-serve refreshes during
// discovery. If both see an expired access token they both refresh with the SAME refresh token. One wins;
// the other gets invalid_grant. Worse, whichever writes last can persist a token the provider has already
// revoked — and then EVERY future refresh fails. The operator is locked out of a server they authorized,
// with no obvious cause, until they sign in again.
//
// The requirement: concurrent Bearer() calls must all succeed, and the token left on disk must still work.
func TestConcurrentRefreshDoesNotLockOut(t *testing.T) {
	ctx := context.Background()
	cfg, tok := freshTokens(t, ctx)

	st := oauth.Store{Dir: t.TempDir()}
	if err := st.Save("racy", oauth.State{Config: cfg, Tokens: oauth.Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       time.Now().Add(-time.Second), // expired: every caller wants to refresh
	}}); err != nil {
		t.Fatal(err)
	}

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	toks := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = st.Bearer(ctx, nil, "racy")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Bearer #%d failed: %v", i, err)
		} else if toks[i] == "" {
			t.Errorf("concurrent Bearer #%d returned an empty token", i)
		}
	}

	// The decisive assertion: whatever ended up on disk must still be usable. A revoked refresh token
	// persisted here means the next connect fails and the operator is locked out.
	after, err := st.Load("racy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := cfg.Refresh(ctx, nil, after.Tokens.RefreshToken); err != nil {
		t.Fatalf("the refresh token left on disk is DEAD — the operator is locked out: %v", err)
	}
}
