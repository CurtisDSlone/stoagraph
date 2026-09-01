package auth_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
)

func req(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/approvals/x/approve", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

var tokens = auth.Tokens{Admin: "A-admin", Approve: "B-approve", Dispatch: "C-dispatch", Operator: "D-operator"}

// TestDispatchCannotApprove is THE load-bearing test (Planning/31): the orchestrator's credential must
// never open the door that mints a signed release. If this ever passes a dispatch token, a hijacked
// orchestrator can self-approve its escalations and the human gate is decorative.
func TestDispatchCannotApprove(t *testing.T) {
	a := &auth.Authenticator{Tokens: tokens}

	if a.Allow(req(tokens.Dispatch), auth.RoleApprove) {
		t.Fatal("SECURITY BREACH: the dispatch (orchestrator) token was admitted to an approve-only route")
	}
	if a.Allow(req(tokens.Dispatch), auth.RoleAdmin) {
		t.Fatal("SECURITY BREACH: the dispatch token was admitted to an admin (policy CRUD) route")
	}
	// and the roles it IS entitled to still work
	if !a.Allow(req(tokens.Dispatch), auth.RoleDispatch) {
		t.Error("dispatch token must be admitted to a dispatch route")
	}
	// the human's approve token opens approve
	if !a.Allow(req(tokens.Approve), auth.RoleApprove) {
		t.Error("approve token must be admitted to an approve route")
	}
	// a read route admits any valid role
	for _, tok := range []string{tokens.Admin, tokens.Approve, tokens.Dispatch} {
		if !a.Allow(req(tok), auth.RoleAdmin, auth.RoleApprove, auth.RoleDispatch) {
			t.Errorf("a multi-role read route should admit %q", tok)
		}
	}
}

// TestOnlyDropsSecretsTheHolderIsNotEntitledTo closes the hole that the HTTP role check alone does not.
//
// The gate rejects a `dispatch` bearer on an approve route — but a compromised orchestrator would never
// send `dispatch` there. It would send the `approve` token it was HOLDING, because the shared tokens
// file contains all four. Holding a secret you never use is still holding it. The orchestrator must
// therefore narrow at load and physically not possess `approve`.
func TestOnlyDropsSecretsTheHolderIsNotEntitledTo(t *testing.T) {
	// what harness-serve keeps
	orch := tokens.Only(auth.RoleDispatch, auth.RoleOperator)

	if orch.Approve != "" {
		t.Fatal("SECURITY: the orchestrator retained the `approve` secret — it can forge a human decision")
	}
	if orch.Admin != "" {
		t.Fatal("SECURITY: the orchestrator retained the `admin` secret — it can rewrite policy")
	}
	if orch.Dispatch != tokens.Dispatch || orch.Operator != tokens.Operator {
		t.Fatalf("the orchestrator must keep exactly what it needs: %+v", orch)
	}

	// and it cannot present what it does not have: even asked to verify the real approve secret,
	// a narrowed set fails closed (an unset expectation admits nobody).
	if orch.Verify(auth.RoleApprove, tokens.Approve) {
		t.Fatal("SECURITY: a narrowed token set still verified an approve secret")
	}

	// what the daemon keeps: `dispatch` alone
	daemon := tokens.Only(auth.RoleDispatch)
	if daemon.Approve != "" || daemon.Admin != "" || daemon.Operator != "" {
		t.Errorf("the daemon should keep only dispatch: %+v", daemon)
	}

	// narrowing nothing keeps nothing (fail closed, never fail open)
	if (auth.Tokens{}.Only()) != (auth.Tokens{}) {
		t.Error("Only() with no roles must yield an empty set")
	}
}

func TestFailClosed(t *testing.T) {
	a := &auth.Authenticator{Tokens: tokens}

	if a.Allow(req(""), auth.RoleAdmin) {
		t.Error("no bearer must be rejected")
	}
	if a.Allow(req("wrong"), auth.RoleAdmin) {
		t.Error("a wrong token must be rejected")
	}
	// an UNSET role admits nobody (it must never fall open)
	empty := &auth.Authenticator{Tokens: auth.Tokens{}}
	if empty.Allow(req("anything"), auth.RoleAdmin) {
		t.Error("an unconfigured role must admit NOBODY, not everybody")
	}
	if empty.Allow(req(""), auth.RoleAdmin) {
		t.Error("unconfigured + no token must be rejected")
	}
	// a nil authenticator is closed, not open
	var nilA *auth.Authenticator
	if nilA.Allow(req(tokens.Admin), auth.RoleAdmin) {
		t.Error("a nil authenticator must fail closed")
	}
	// malformed header
	r := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	r.Header.Set("Authorization", tokens.Admin) // missing "Bearer "
	if a.Allow(r, auth.RoleAdmin) {
		t.Error("a non-Bearer Authorization header must be rejected")
	}
}

func TestGuard401AndPassthrough(t *testing.T) {
	a := &auth.Authenticator{Tokens: tokens}
	hit := false
	h := a.Guard(auth.RoleApprove)(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	})

	// dispatch token -> 401, handler NEVER runs
	w := httptest.NewRecorder()
	h(w, req(tokens.Dispatch))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("dispatch on approve route: got %d, want 401", w.Code)
	}
	if hit {
		t.Fatal("SECURITY BREACH: the guarded handler ran for an unauthorized role")
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 should carry WWW-Authenticate")
	}

	// approve token -> through
	w2 := httptest.NewRecorder()
	h(w2, req(tokens.Approve))
	if w2.Code != http.StatusOK || !hit {
		t.Errorf("approve on approve route: got %d, hit=%v", w2.Code, hit)
	}
}

func TestDevNoAuthBypasses(t *testing.T) {
	a := &auth.Authenticator{Tokens: tokens, Disabled: true}
	if !a.Allow(req(""), auth.RoleApprove) {
		t.Error("-dev-no-auth must bypass (it is the explicit local escape hatch)")
	}
}

func TestLoadOrGenerateThenLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.tokens")

	got, generated, err := auth.LoadOrGenerate(path)
	if err != nil || !generated {
		t.Fatalf("first run must generate: generated=%v err=%v", generated, err)
	}
	// four DISTINCT, non-empty secrets — a shared secret would defeat the whole role split
	set := map[string]bool{got.Admin: true, got.Approve: true, got.Dispatch: true, got.Operator: true}
	if len(set) != 4 || got.Admin == "" || got.Approve == "" || got.Dispatch == "" || got.Operator == "" {
		t.Fatalf("expected 4 distinct non-empty tokens, got %+v", got)
	}
	// persisted 0600 (it is a secret on disk)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("tokens file perms = %o, want 600", perm)
	}
	// second run loads the SAME tokens (stable across restarts)
	again, generated2, err := auth.LoadOrGenerate(path)
	if err != nil || generated2 {
		t.Fatalf("second run must load, not regenerate: generated=%v err=%v", generated2, err)
	}
	if again != got {
		t.Errorf("tokens changed across restart: %+v vs %+v", again, got)
	}
	// a consumer (daemon/harness) can Load them
	loaded, err := auth.Load(path)
	if err != nil || loaded != got {
		t.Fatalf("Load: %+v err=%v", loaded, err)
	}
	// Load on a missing file with no env FAILS (a consumer must not invent a secret nobody knows)
	if _, err := auth.Load(filepath.Join(dir, "nope.tokens")); err == nil {
		t.Error("Load of a missing tokens file must error, not silently succeed")
	}
}

func TestEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.tokens")
	if _, _, err := auth.LoadOrGenerate(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STAG_DISPATCH_TOKEN", "from-env")

	got, err := auth.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Dispatch != "from-env" {
		t.Errorf("env must override the file (container secrets): got %q", got.Dispatch)
	}
	a := &auth.Authenticator{Tokens: got}
	if !a.Allow(req("from-env"), auth.RoleDispatch) {
		t.Error("the env-supplied token should authenticate")
	}
}
