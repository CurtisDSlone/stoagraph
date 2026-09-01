package serve_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

var toks = auth.Tokens{Admin: "tok-admin", Approve: "tok-approve", Dispatch: "tok-dispatch", Operator: "tok-operator"}

func guardedServer(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return (&serve.Server{
		Gate:    proxy.Gate{Routes: proxy.Router{}},
		Recipes: recipestore.Store{Dir: t.TempDir()},
		Store:   st,
		Auth:    &auth.Authenticator{Tokens: toks}, // auth ON (not Disabled)
	}).Handler()
}

func status(t *testing.T, h http.Handler, method, path, token string) int {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// TestRoleMap pins the Planning/31 endpoint→role table at the HTTP layer. It asserts only 401 vs
// not-401 — a route may legitimately 400/404 on this body; the contract under test is WHO gets in.
func TestRoleMap(t *testing.T) {
	h := guardedServer(t)

	cases := []struct {
		method, path string
		allowed      []string // tokens that must NOT get 401
		denied       []string // tokens (and "" = none) that MUST get 401
	}{
		// approve mints the signed release — the HUMAN's token only.
		{"POST", "/api/approvals/abc/approve", []string{toks.Approve}, []string{toks.Dispatch, toks.Admin, toks.Operator, ""}},
		{"POST", "/api/approvals/abc/deny", []string{toks.Approve}, []string{toks.Dispatch, toks.Admin, toks.Operator, ""}},

		// policy CRUD — rewriting a recipe is a total bypass, so: admin only.
		{"POST", "/api/recipes", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"DELETE", "/api/recipes/x", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"POST", "/api/routes", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"DELETE", "/api/routes/srv/x", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}}, // {server}/{tool}
		{"POST", "/api/mcp-servers", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"DELETE", "/api/mcp-servers/x", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"POST", "/api/providers", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},
		{"DELETE", "/api/providers/x", []string{toks.Admin}, []string{toks.Dispatch, toks.Approve, ""}},

		// reads + the approval POLL — any valid role (the orchestrator MUST be able to wait on its
		// own escalation), but never an anonymous caller.
		{"GET", "/api/routes", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"GET", "/api/recipes", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"GET", "/api/providers", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"GET", "/api/mcp-servers", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"GET", "/api/approvals", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"GET", "/api/approvals/abc", []string{toks.Admin, toks.Approve, toks.Dispatch}, []string{""}},
		{"POST", "/api/decide", []string{toks.Admin, toks.Dispatch}, []string{""}},
		{"GET", "/api/log", []string{toks.Admin, toks.Dispatch}, []string{""}},
	}

	for _, c := range cases {
		for _, tok := range c.allowed {
			if code := status(t, h, c.method, c.path, tok); code == http.StatusUnauthorized {
				t.Errorf("%s %s: token %q should be ADMITTED, got 401", c.method, c.path, tok)
			}
		}
		for _, tok := range c.denied {
			if code := status(t, h, c.method, c.path, tok); code != http.StatusUnauthorized {
				name := tok
				if name == "" {
					name = "<anonymous>"
				}
				t.Errorf("SECURITY: %s %s admitted %s (got %d, want 401)", c.method, c.path, name, code)
			}
		}
	}
}

// TestHealthStaysOpen — liveness must not need a credential (containers probe it).
func TestHealthStaysOpen(t *testing.T) {
	h := guardedServer(t)
	if code := status(t, h, "GET", "/api/health", ""); code != http.StatusOK {
		t.Errorf("health must stay open for probes: got %d", code)
	}
}

// TestNilAuthFailsClosed — a Server built without an Authenticator must LOCK, not fall open. This is
// the misconfiguration that would otherwise ship a wide-open control plane.
func TestNilAuthFailsClosed(t *testing.T) {
	h := (&serve.Server{
		Gate:    proxy.Gate{Routes: proxy.Router{}},
		Recipes: recipestore.Store{Dir: t.TempDir()},
	}).Handler() // Auth is nil
	for _, c := range [][2]string{{"POST", "/api/approvals/x/approve"}, {"POST", "/api/recipes"}, {"GET", "/api/routes"}} {
		if code := status(t, h, c[0], c[1], "anything"); code != http.StatusUnauthorized {
			t.Errorf("SECURITY: nil Auth fell OPEN on %s %s (got %d, want 401)", c[0], c[1], code)
		}
	}
}
