package recipe

import (
	"strings"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

const foreachSrc = `recipe: batch_policy
version: 1
rules:
  action.allowed:
    kind: set_membership
    set: ["restart", "scale"]
steps:
  - id: propose_plan
    kind: propose
    out: plan
  - id: each
    kind: foreach
    in: plan
    as: item
  - id: apply
    kind: sink
    in: item
    field: mcp.exec.action
    sensitivity: authoritative
    rule: action.allowed
    actor: "policy:batch"
`

func TestForeachRecipeParsesAndEvals(t *testing.T) {
	p, err := Parse([]byte(foreachSrc))
	if err != nil {
		t.Fatalf("foreach recipe must parse: %v", err)
	}
	fe := p.Recipe.Steps[1]
	if fe.Kind != stag.NodeForeach || fe.In != "plan" || fe.As != "item" {
		t.Fatalf("foreach step: %+v", fe)
	}
	if _, w, derr := ParseDraft([]byte(foreachSrc)); derr != nil || len(w) != 0 {
		t.Fatalf("draft: warnings=%v err=%v", w, derr)
	}

	// evaluates per element (matches U28)
	res := stag.Eval(p.Recipe, `["restart","scale"]`, p.SemanticHash)
	if res.Verdict != stag.Allow || len(res.Events) != 2 {
		t.Errorf("all-allowed batch: %+v", res)
	}
	res = stag.Eval(p.Recipe, `["restart","nope"]`, p.SemanticHash)
	if res.Verdict != stag.Deny || len(res.Events) != 1 {
		t.Errorf("one-denied batch: %+v", res)
	}
}

func TestForeachLintRejects(t *testing.T) {
	cases := map[string]string{
		"missing as":    strings.Replace(foreachSrc, "    as: item\n", "", 1),
		"missing in":    strings.Replace(foreachSrc, "    in: plan\n", "", 1),
		"duplicate as":  strings.Replace(foreachSrc, "    as: item", "    as: plan", 1),
		"undeclared in": strings.Replace(foreachSrc, "    in: plan\n    as: item", "    in: nope\n    as: item", 1),
		"illegal key":   strings.Replace(foreachSrc, "    as: item\n", "    as: item\n    rule: action.allowed\n", 1),
		"two foreach": strings.Replace(foreachSrc, "  - id: apply\n",
			"  - id: each2\n    kind: foreach\n    in: item\n    as: sub\n  - id: apply\n", 1),
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestExitParsesAsTerminal(t *testing.T) {
	// exit is now a real terminal kind (implemented for composition). A recipe ending in
	// exit parses, and the compiled step is NodeExit.
	src := "recipe: r\nversion: 1\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: done\n    kind: exit\n"
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("exit terminal must parse: %v", err)
	}
	last := p.Recipe.Steps[len(p.Recipe.Steps)-1]
	if last.Kind != stag.NodeExit {
		t.Fatalf("last step must be NodeExit, got %v", last.Kind)
	}
}
