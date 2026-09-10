package oauth_test

// kw-test: token-endpoint client auth is PER-PROVIDER — basic vs post, negotiated from metadata + fallback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
)

// asServing stands up an authorization server that advertises `methods` and accepts ONLY `accept`.
// It records which method the client actually used.
func asServing(t *testing.T, methods []string, accept string, used *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
		}
		if methods != nil {
			doc["token_endpoint_auth_methods_supported"] = methods
		}
		writeJSON(w, doc)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, hasBasic := r.BasicAuth()

		var method string
		switch {
		case hasBasic:
			method = oauth.AuthBasic
		case r.Form.Get("client_secret") != "":
			method = oauth.AuthPost
		default:
			method = oauth.AuthNone
		}
		*used = method

		if method != accept {
			// exactly how a real provider refuses the wrong client-auth method
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"error": "invalid_client"})
			return
		}
		if method == oauth.AuthBasic && (id == "" || secret == "") {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"error": "invalid_client"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "at-" + method, "token_type": "Bearer", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

// TestTokenAuthBasicOnlyProvider is the interop bug this negotiation exists to prevent. The RFC makes
// client_secret_basic MANDATORY for servers and leaves client_secret_post optional, so a provider that
// takes ONLY Basic is entirely legitimate — and the old code, which always put the secret in the body,
// would have been rejected with invalid_client and never recovered.
func TestTokenAuthBasicOnlyProvider(t *testing.T) {
	var used string
	srv := asServing(t, []string{oauth.AuthBasic}, oauth.AuthBasic, &used)
	defer srv.Close()
	ctx := context.Background()

	cfg, err := oauth.Discover(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if cfg.TokenAuthMethod != oauth.AuthBasic {
		t.Fatalf("discovery must adopt the provider's advertised method, got %q", cfg.TokenAuthMethod)
	}
	cfg.ClientID, cfg.ClientSecret = "cid", "csecret"

	tok, err := cfg.Exchange(ctx, srv.Client(), "http://localhost:8080"+oauth.CallbackPath, "code", "verifier")
	if err != nil {
		t.Fatalf("a Basic-only provider must be handled: %v", err)
	}
	if used != oauth.AuthBasic {
		t.Fatalf("expected Basic auth on the token request, used %q", used)
	}
	if tok.AccessToken != "at-"+oauth.AuthBasic {
		t.Fatalf("unexpected token: %q", tok.AccessToken)
	}
}

// TestTokenAuthPostProvider — the other side: a provider that takes the secret in the body.
func TestTokenAuthPostProvider(t *testing.T) {
	var used string
	srv := asServing(t, []string{oauth.AuthPost}, oauth.AuthPost, &used)
	defer srv.Close()
	ctx := context.Background()

	cfg, err := oauth.Discover(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	cfg.ClientID, cfg.ClientSecret = "cid", "csecret"
	if _, err := cfg.Exchange(ctx, srv.Client(), "http://x"+oauth.CallbackPath, "code", "v"); err != nil {
		t.Fatalf("post provider: %v", err)
	}
	if used != oauth.AuthPost {
		t.Fatalf("expected form-body auth, used %q", used)
	}
}

// TestTokenAuthUndeclaredFallsBack — a provider that advertises NOTHING but accepts only Basic. We try
// the body first, get invalid_client, and must recover by retrying with Basic rather than giving up.
func TestTokenAuthUndeclaredFallsBack(t *testing.T) {
	var used string
	srv := asServing(t, nil, oauth.AuthBasic, &used) // no metadata about auth methods
	defer srv.Close()
	ctx := context.Background()

	cfg, err := oauth.Discover(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if cfg.TokenAuthMethod != "" {
		t.Fatalf("nothing was advertised; method should be undeclared, got %q", cfg.TokenAuthMethod)
	}
	cfg.ClientID, cfg.ClientSecret = "cid", "csecret"

	tok, err := cfg.Exchange(ctx, srv.Client(), "http://x"+oauth.CallbackPath, "code", "v")
	if err != nil {
		t.Fatalf("must fall back to Basic when the body form is refused: %v", err)
	}
	if used != oauth.AuthBasic {
		t.Fatalf("fallback should have landed on Basic, used %q", used)
	}
	if tok.AccessToken == "" {
		t.Fatal("no token after fallback")
	}
}

// TestTokenAuthNoRetryOnBadGrant — a spent/invalid code must NOT be retried. Replaying it with the other
// auth method just burns the code again and muddies the error.
func TestTokenAuthNoRetryOnBadGrant(t *testing.T) {
	attempts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "invalid_grant"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := oauth.Config{TokenEndpoint: srv.URL + "/token", ClientID: "cid", ClientSecret: "csecret"}
	if _, err := cfg.Exchange(context.Background(), srv.Client(), "http://x"+oauth.CallbackPath, "spent", "v"); err == nil {
		t.Fatal("an invalid_grant must fail")
	}
	if attempts != 1 {
		t.Fatalf("a bad grant must not be retried with another auth method; token endpoint hit %d times", attempts)
	}
}
