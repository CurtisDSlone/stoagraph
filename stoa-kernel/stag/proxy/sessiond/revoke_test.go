package sessiond_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
)

func deleteSession(t *testing.T, base, bearer, tok string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, base+"/sessions/"+tok, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /sessions/%s: %v", tok, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// Revocation is the only way to withdraw authority from a running agent: a binding holds a COMPILED
// copy of its recipes, so deleting the recipe or route does not disarm it. After a revoke the token
// must stop resolving entirely.
func TestRevokeClosesTheSession(t *testing.T) {
	ts := guardedDaemon(t, &auth.Authenticator{Tokens: testTokens})
	ctx := context.Background()

	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")
	sess, err := connectMCP(ctx, ts.URL, tok)
	if err != nil {
		t.Fatalf("the session must work before revocation: %v", err)
	}
	sess.Close()

	if code := deleteSession(t, ts.URL, testTokens.Dispatch, tok); code != http.StatusOK {
		t.Fatalf("revoke by the dispatch role: got %d, want 200", code)
	}
	// fail closed: an unbound token is served nothing at all.
	if _, err := connectMCP(ctx, ts.URL, tok); err == nil {
		t.Error("SECURITY: a revoked token still resolved to a gate")
	}
	// and revoking twice reports the miss rather than a silent success.
	if code := deleteSession(t, ts.URL, testTokens.Dispatch, tok); code != http.StatusNotFound {
		t.Errorf("second revoke: got %d, want 404", code)
	}
}

// An agent that could revoke — or rebind — itself would be choosing its own policy, which is exactly
// what the trusted binder exists to prevent. The session token is NOT a control-plane credential.
func TestRevokeRequiresDispatchRole(t *testing.T) {
	ts := guardedDaemon(t, &auth.Authenticator{Tokens: testTokens})
	tok := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")

	for _, tc := range []struct{ name, bearer string }{
		{"anonymous", ""},
		{"bogus", "not-the-token"},
		{"the agent's own session token", tok},
		{"the human's approve secret", testTokens.Approve},
	} {
		if code := deleteSession(t, ts.URL, tc.bearer, tok); code != http.StatusUnauthorized {
			t.Errorf("SECURITY: %s revoked a session (got %d, want 401)", tc.name, code)
		}
	}
	// the binder's own role still works, so the guard is not simply refusing everyone.
	if code := deleteSession(t, ts.URL, testTokens.Dispatch, tok); code != http.StatusOK {
		t.Errorf("the dispatch role must be able to revoke: got %d", code)
	}
}

// A daemon wired without an Authenticator must refuse revocation too, not fall open.
func TestRevokeNilAuthFailsClosed(t *testing.T) {
	ts := guardedDaemon(t, nil)
	if code := deleteSession(t, ts.URL, testTokens.Dispatch, "sometoken"); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: nil Auth fell OPEN on DELETE /sessions (got %d, want 401)", code)
	}
}
