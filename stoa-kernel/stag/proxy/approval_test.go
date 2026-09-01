package proxy_test

import (
	"context"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// An approval-gated recipe: prod is released ONLY when a signed_equality "$approved" gate on the
// approval_token passes. No/invalid token -> the gate fails -> escalate. The proxy resolves the
// "$approved" placeholder from the approval store at eval time.
const apprSrc = `recipe: appr_test
version: 1
passthrough: ["deployment"]
rules:
  approved: {kind: signed_equality, signed: "$approved"}
  is_prod:  {kind: set_membership, set: ["prod"]}
steps:
  - {id: p_ns, kind: propose, out: namespace}
  - {id: p_tok, kind: propose, out: approval_token}
  - {id: gate_appr, kind: gate, in: approval_token, rule: approved, on_fail: escalate}
  - {id: apply, kind: sink, in: namespace, field: k8s.apply, sensitivity: authoritative, rule: is_prod, actor: "policy:test", goto: done}
  - {id: done, kind: exit}
`

// fakeAppr is an in-memory proxy.Approvals for the loop test.
type fakeAppr struct {
	tokenByFP map[string]string // fingerprint -> approved token
	idByFP    map[string]string
	pending   map[string]bool // id -> recorded
	consumed  map[string]bool
	records   int
}

func newFakeAppr() *fakeAppr {
	return &fakeAppr{tokenByFP: map[string]string{}, idByFP: map[string]string{}, pending: map[string]bool{}, consumed: map[string]bool{}}
}

func (f *fakeAppr) LookupApproved(_ context.Context, fp string) (string, string, bool, error) {
	if t, ok := f.tokenByFP[fp]; ok {
		return t, f.idByFP[fp], true, nil
	}
	return "", "", false, nil
}

func (f *fakeAppr) RecordPending(_ context.Context, id, _, _, _, _, _ string) (bool, error) {
	if f.pending[id] {
		return false, nil
	}
	f.pending[id] = true
	f.records++
	return true, nil
}

func (f *fakeAppr) Consume(_ context.Context, id string) error {
	f.consumed[id] = true
	for fp, i := range f.idByFP { // a consumed release no longer looks up (replay re-escalates)
		if i == id {
			delete(f.tokenByFP, fp)
			delete(f.idByFP, fp)
		}
	}
	return nil
}

func apprRouter(t testing.TB) proxy.Router {
	t.Helper()
	p, err := recipe.Parse([]byte(apprSrc))
	if err != nil {
		t.Fatalf("approval recipe must parse+lint: %v", err)
	}
	return proxy.Router{
		"scale_deployment": {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "namespace,approval_token", RecipeName: "appr_test"},
	}
}

// The full Stage-5 loop, deterministic and DB-free: escalate -> approve -> release+consume ->
// replay re-escalates.
func TestApprovalLoop(t *testing.T) {
	appr := newFakeAppr()
	notified := 0
	g := proxy.Gate{
		Routes:     apprRouter(t),
		Approvals:  appr,
		OnEscalate: func(_ context.Context, _ proxy.PendingNotice) { notified++ },
	}
	scaleProd := func(token string) proxy.Decision {
		args := map[string]string{"namespace": "prod", "deployment": "web"}
		if token != "" {
			args[proxy.MetaApprovalToken] = token
		}
		return g.Decide(context.Background(), proxy.ToolCall{Tool: "scale_deployment", Args: args})
	}

	// 1. no token -> escalate, a pending approval is recorded + the webhook fires once.
	d1 := scaleProd("")
	if d1.Verdict != stag.Escalate || d1.Forward {
		t.Fatalf("unapproved prod scale must escalate (not forward): %+v", d1)
	}
	if d1.ApprovalID == "" || appr.records != 1 || notified != 1 {
		t.Fatalf("escalate must record one pending approval + notify once: id=%q records=%d notified=%d", d1.ApprovalID, appr.records, notified)
	}

	// re-escalating the same action is idempotent: no new record, no new notification.
	_ = scaleProd("")
	if appr.records != 1 || notified != 1 {
		t.Fatalf("re-escalate must be idempotent: records=%d notified=%d", appr.records, notified)
	}

	// 2. a human approves: mint a token bound to this action's fingerprint.
	fp := proxy.Fingerprint("scale_deployment", map[string]string{"namespace": "prod", "deployment": "web"})
	const token = "SIGNED-RELEASE-TOKEN"
	appr.tokenByFP[fp] = token
	appr.idByFP[fp] = d1.ApprovalID

	// wrong token still escalates (only the exact minted token releases).
	if d := scaleProd("guessed"); d.Verdict != stag.Escalate || d.Forward {
		t.Fatalf("a wrong approval_token must still escalate: %+v", d)
	}
	// the placeholder literal must NOT bypass the gate.
	if d := scaleProd("$approved"); d.Verdict != stag.Escalate || d.Forward {
		t.Fatalf("the $approved placeholder must never release: %+v", d)
	}

	// 3. retry with the minted token -> release (Allow+forward), and the release is consumed.
	d3 := scaleProd(token)
	if d3.Verdict != stag.Allow || !d3.Forward {
		t.Fatalf("approved retry must release+forward: %+v", d3)
	}
	if len(d3.Events) == 0 {
		t.Errorf("release must emit a ReleaseEvent (the audit crossing): %+v", d3)
	}
	if !appr.consumed[d1.ApprovalID] {
		t.Fatalf("release must consume the one-time approval")
	}

	// 4. replay the same token -> re-escalates (one-time release spent).
	if d := scaleProd(token); d.Verdict != stag.Escalate || d.Forward {
		t.Fatalf("a consumed token must re-escalate (no replay): %+v", d)
	}
}
