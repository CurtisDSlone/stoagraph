package proxy

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// THE HUMAN-APPROVAL LOOP ACROSS EVERY STEP KIND.
//
// A `signed_equality` rule whose expected value is "$approved" escalates until a person mints a
// signed release for that exact action; the retried call then passes. Both halves of that —
// noticing the recipe participates, and substituting the token — walked only Step.Rule and
// Step.Cases, which predate invoke, await and read. Those carry their rules in ArgRules, Until
// and QueryRule, so a $approved rule there was NEVER detected and NEVER substituted.
//
// The failure is fail-CLOSED but it is not benign: the placeholder is compared literally, so the
// rule can never pass. A human approves and the call is refused anyway — a policy that cannot be
// satisfied by the mechanism it names.

type stubApprovals struct {
	token, id string
	approved  bool
	pending   []string
	consumed  []string
}

func (s *stubApprovals) LookupApproved(_ context.Context, fp string) (string, string, bool, error) {
	if s.approved {
		return s.token, s.id, true, nil
	}
	return "", "", false, nil
}

func (s *stubApprovals) RecordPending(_ context.Context, id, tool, fp, argsJSON, recipe, hash string) (bool, error) {
	s.pending = append(s.pending, id)
	return true, nil
}

func (s *stubApprovals) Consume(_ context.Context, id string) error {
	s.consumed = append(s.consumed, id)
	return nil
}

func approvedRule() *stag.ReleaseRule {
	return &stag.ReleaseRule{Kind: stag.RuleSignedEquality, Signed: "$approved"}
}

// Every step kind that can carry a rule must be seen by the approval detector.
func TestApprovalGateIsDetectedOnEveryStepKind(t *testing.T) {
	cases := []struct {
		name string
		step stag.Step
	}{
		{"sink", stag.Step{Id: "s", Kind: stag.NodeSink, In: "v", Field: "f",
			Sensitivity: stag.SinkAuthoritative, Rule: approvedRule(), RuleID: "r", Actor: "a"}},
		{"gate", stag.Step{Id: "g", Kind: stag.NodeGate, In: "v", Rule: approvedRule(), RuleID: "r"}},
		{"invoke argument", stag.Step{Id: "i", Kind: stag.NodeInvoke, Tool: "t", Actor: "a",
			ArgRules: map[string]stag.ArgRule{"x": {Slot: "v", Rule: approvedRule(), RuleID: "r"}}}},
		{"await argument", stag.Step{Id: "w", Kind: stag.NodeAwait, Tool: "t", Actor: "a",
			ArgRules: map[string]stag.ArgRule{"x": {Slot: "v", Rule: approvedRule(), RuleID: "r"}},
			Until:    &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"done"}},
			UntilID:  "d", Attempts: 2, DelayMS: 1}},
		{"read query", stag.Step{Id: "rd", Kind: stag.NodeRead, Provider: "p",
			QuerySlot: "v", QueryRule: approvedRule(), QueryRuleID: "r"}},
	}
	for _, c := range cases {
		r := stag.Recipe{Steps: []stag.Step{{Id: "p", Kind: stag.NodePropose, Out: "v"}, c.step}}
		if !recipeHasApprovalGate(r) {
			t.Errorf("%s: a $approved rule here must put the recipe in the approval loop", c.name)
		}
	}
}

// And the token must actually be substituted, or the approval can never be redeemed.
func TestApprovedTokenIsSubstitutedOnEveryStepKind(t *testing.T) {
	const tok = "SIGNED-RELEASE"
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "v"},
		{Id: "i", Kind: stag.NodeInvoke, Tool: "t", Actor: "a",
			ArgRules: map[string]stag.ArgRule{"x": {Slot: "v", Rule: approvedRule(), RuleID: "r"}}},
		{Id: "rd", Kind: stag.NodeRead, Provider: "p", QuerySlot: "v",
			QueryRule: approvedRule(), QueryRuleID: "r"},
	}}
	got := resolveApproved(r, tok)
	if s := got.Steps[1].ArgRules["x"].Rule.Signed; s != tok {
		t.Errorf("invoke argument: expected value is %q, want the minted token", s)
	}
	if s := got.Steps[2].QueryRule.Signed; s != tok {
		t.Errorf("read query: expected value is %q, want the minted token", s)
	}
	// the ORIGINAL recipe must be untouched — the router holds it across calls
	if r.Steps[1].ArgRules["x"].Rule.Signed != "$approved" {
		t.Error("resolveApproved must not mutate the shared parsed recipe")
	}
}

// END TO END: a GATE with on_fail: escalate, guarding an invoke. Unapproved escalates and asks
// a human; approved forwards, authorizes the call, and burns the release.
//
// The escalation must come from a gate. Only a gate produces an Escalate verdict — a failing
// rule anywhere else is a DENY — so a $approved rule sitting directly on an invoke argument
// refuses the call without ever asking anyone. That is fail-closed and useless: the action is
// blocked by a mechanism whose whole purpose is to unblock it. See
// TestApprovedRuleOffAGateNeverAsksAnyone.
func TestInvokeApprovalLoop(t *testing.T) {
	safe := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"prod-db"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "v"},
		{Id: "ask", Kind: stag.NodeGate, In: "v", Rule: approvedRule(),
			RuleID: "needs.approval", Escalate: true},
		{Id: "act", Kind: stag.NodeInvoke, Tool: "srv__danger", Actor: "policy:x",
			ArgRules: map[string]stag.ArgRule{"target": {Slot: "v", Rule: &safe, RuleID: "ok"}}},
	}}
	call := ToolCall{Tool: "t", Args: map[string]string{"v": "prod-db"}}

	// 1. no approval on file -> escalate, and a human is asked
	unapproved := &stubApprovals{}
	g := Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "v"}},
		Approvals: unapproved}
	d := g.Decide(context.Background(), call)
	if d.Forward {
		t.Fatal("an unapproved action must not forward")
	}
	if d.Verdict != stag.Escalate {
		t.Errorf("want escalate, got %v", d.Verdict)
	}
	if len(unapproved.pending) != 1 {
		t.Errorf("a human must be asked: %d pending", len(unapproved.pending))
	}
	if d.ApprovalID == "" {
		t.Error("the agent must be given an id it can poll")
	}
	if len(d.Authorized) != 0 {
		t.Error("and nothing may be authorized while it waits")
	}

	// 2. a human approves this EXACT action -> the retried call forwards
	approved := &stubApprovals{token: "prod-db", id: "ap-1", approved: true}
	g2 := Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "v"}},
		Approvals: approved}
	d2 := g2.Decide(context.Background(), call)
	if !d2.Forward {
		t.Fatalf("an approved action must forward: %+v", d2)
	}
	if len(d2.Authorized) != 1 {
		t.Errorf("and its call must be authorized: %d", len(d2.Authorized))
	}
	if len(approved.consumed) != 1 {
		t.Error("the release is ONE-TIME and must be burned on use")
	}
}

// A $approved rule that is not on a GATE blocks the action and asks nobody. It is fail-closed,
// and it is a policy that can never be satisfied: the approval mechanism it names cannot be
// reached, because only a gate escalates.
func TestApprovedRuleOffAGateNeverAsksAnyone(t *testing.T) {
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "v"},
		{Id: "act", Kind: stag.NodeInvoke, Tool: "srv__danger", Actor: "a",
			ArgRules: map[string]stag.ArgRule{"target": {Slot: "v", Rule: approvedRule(), RuleID: "r"}}},
	}}
	appr := &stubApprovals{}
	g := Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "v"}}, Approvals: appr}
	d := g.Decide(context.Background(), ToolCall{Tool: "t", Args: map[string]string{"v": "prod-db"}})
	if d.Forward {
		t.Fatal("it must not forward")
	}
	if d.Verdict != stag.Deny {
		t.Errorf("a failing rule off a gate is a DENY, not an escalation: %v", d.Verdict)
	}
	if len(appr.pending) != 0 {
		t.Error("and nobody is asked — which is exactly why the approval must sit on a gate")
	}
}

// The approval binds the EXACT action. A release minted for one target must not clear another.
func TestApprovalDoesNotCoverADifferentAction(t *testing.T) {
	safe := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"prod-db", "staging-db"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "v"},
		{Id: "ask", Kind: stag.NodeGate, In: "v", Rule: approvedRule(), RuleID: "r", Escalate: true},
		{Id: "act", Kind: stag.NodeInvoke, Tool: "srv__danger", Actor: "a",
			ArgRules: map[string]stag.ArgRule{"target": {Slot: "v", Rule: &safe, RuleID: "ok"}}},
	}}
	// the human approved "staging-db"; the agent now asks for "prod-db"
	appr := &stubApprovals{token: "staging-db", id: "ap-1", approved: true}
	g := Gate{Routes: Router{"t": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "v"}}, Approvals: appr}
	d := g.Decide(context.Background(), ToolCall{Tool: "t", Args: map[string]string{"v": "prod-db"}})
	if d.Forward {
		t.Fatal("an approval for one action must not clear a different one")
	}
}
