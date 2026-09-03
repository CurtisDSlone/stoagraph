package recipe

import "strings"

import "testing"

// The recipe boundary for `invoke`: an authored step that AUTHORIZES a tool call. The
// linter's job is that a recipe which could authorize something unreviewable is a
// REJECTED FILE, not a runtime surprise.

const invokeSrc = `
recipe: drain_policy
version: 1
rules:
  ns.safe: {kind: set_membership, set: ["dev", "staging"]}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: drain, kind: invoke, tool: k8s.drain, args: {node: {slot: ns, rule: ns.safe}}, actor: "policy:platform"}
  - {id: check, kind: invoke, tool: k8s.status, args: {node: {slot: ns, rule: ns.safe}}, actor: "policy:platform"}
`

func TestInvokeParses(t *testing.T) {
	p, err := Parse([]byte(invokeSrc))
	if err != nil {
		t.Fatalf("valid invoke recipe must parse: %v", err)
	}
	if len(p.Recipe.Steps) != 3 {
		t.Fatalf("want 3 steps, got %d", len(p.Recipe.Steps))
	}
	drain := p.Recipe.Steps[1]
	if drain.Tool != "k8s.drain" {
		t.Errorf("tool not compiled: %q", drain.Tool)
	}
	if drain.ArgRules["node"].Slot != "ns" {
		t.Errorf("args must compile as argname -> slot: %+v", drain.ArgRules)
	}
	if drain.ArgRules["node"].Rule == nil || drain.ArgRules["node"].RuleID != "ns.safe" {
		t.Errorf("invoke must bind its rule: %+v", drain)
	}
}

// The tool and args ride in the SEMANTIC hash: changing which tool a recipe authorizes,
// or which slot feeds an argument, is a different policy and the audit must say so.
func TestInvokeRidesInSemanticHash(t *testing.T) {
	base, err := Parse([]byte(invokeSrc))
	if err != nil {
		t.Fatal(err)
	}
	// same shape, different tool
	other, err := Parse([]byte(strings.Replace(invokeSrc, "tool: k8s.drain", "tool: k8s.delete", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if base.SemanticHash == other.SemanticHash {
		t.Error("changing the authorized tool must change the semantic hash")
	}
	// same tool, different source slot
	argSwap := strings.Replace(invokeSrc, "args: {node: {slot: ns, rule: ns.safe}}, actor: \"policy:platform\"}\n  - {id: check", "args: {host: {slot: ns, rule: ns.safe}}, actor: \"policy:platform\"}\n  - {id: check", 1)
	swapped, err := Parse([]byte(argSwap))
	if err != nil {
		t.Fatal(err)
	}
	if base.SemanticHash == swapped.SemanticHash {
		t.Error("changing an argument name must change the semantic hash")
	}
}

// Fail closed at the boundary: an invoke missing any load-bearing part is rejected.
func TestInvokeRejectsMalformed(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no tool", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, args: {node: {slot: ns, rule: ok}}, actor: a}
`},
		{"no args", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, actor: a}
`},
		{"no rule", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: ns}}, actor: a}
`},
		{"empty args map", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {}, actor: a}
`},
		{"unknown rule ref", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: ns, rule: nope}}, actor: a}
`},
		{"illegal key", `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: ns, rule: ok}}, actor: a, sensitivity: authoritative}
`},
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c.src)); err == nil {
			t.Errorf("%s: must be rejected", c.name)
		}
	}
}

// declare-before-use reaches into an invoke's arguments: a call cannot be fed from a
// slot that no step has bound.
func TestInvokeArgMustBeDeclared(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: undeclared, rule: ok}}, actor: a}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("an invoke arg fed by an undeclared slot must be rejected")
	}
}

// foreach x invoke is the ONE construct where an attacker-chosen list length multiplies
// author-written calls. Refused at the boundary, not merely faulted at runtime.
func TestInvokeInsideForeachRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: list}
  - {id: fe, kind: foreach, in: list, as: item}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: item, rule: ok}}, actor: a}
`
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("invoke inside a foreach body must be rejected")
	}
	if !strings.Contains(err.Error(), "foreach") {
		t.Errorf("the error must name the construct it refuses: %v", err)
	}
}

// Two invokes may not authorize the same tool twice: the same uniqueness discipline the
// authoritative sinks already have, so one action cannot be claimed by two steps.
func TestInvokeToolMustBeUnique(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: a, kind: invoke, tool: k8s.drain, args: {node: {slot: ns, rule: ok}}, actor: a}
  - {id: b, kind: invoke, tool: k8s.drain, args: {node: {slot: ns, rule: ok}}, actor: a}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("two invokes authorizing the same tool must be rejected")
	}
}

// An authored recipe may not exceed the authorization cap: a bound on how many actions
// one policy may authorize, so a reviewer can always read the whole sequence.
func TestInvokeCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("recipe: r\nversion: 1\nrules: {ok: {kind: set_membership, set: [\"dev\"]}}\nsteps:\n  - {id: p, kind: propose, out: ns}\n")
	for i := 0; i <= invokeCap; i++ {
		b.WriteString("  - {id: i")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + i/26)))
		b.WriteString(", kind: invoke, tool: t")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + i/26)))
		b.WriteString(", args: {node: {slot: ns, rule: ok}}, actor: a}\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Errorf("a recipe over the invoke cap (%d) must be rejected", invokeCap)
	}
}

// An invoke naming an authoritative-looking tool raises a CAUTION, not a rejection —
// the reviewer sees it, which is the point of writing it down.
func TestInvokeAuthoritativeToolCautions(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: k8s.delete_namespace, args: {node: {slot: ns, rule: ok}}, actor: a}
`
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("a cautioned recipe must still parse: %v", err)
	}
	cs := Cautions(p)
	found := false
	for _, c := range cs {
		if strings.Contains(c, "k8s.delete_namespace") {
			found = true
		}
	}
	if !found {
		t.Errorf("an invoke on a destructive-looking tool must caution: %v", cs)
	}
}

// PER-ARGUMENT RULES ARE THE POINT. Each argument names its own rule, and the rule an
// argument is cleared by is part of the policy's identity — swapping two arguments' rules
// is a different policy even though the same rules and slots appear.
func TestPerArgumentRulesRideInSemanticHash(t *testing.T) {
	base := `
recipe: r
version: 1
rules:
  img: {kind: set_membership, set: ["badport"]}
  port: {kind: set_membership, set: ["8080"]}
steps:
  - {id: p_i, kind: propose, out: image}
  - {id: p_v, kind: propose, out: value}
  - {id: fix, kind: invoke, tool: t,
     args: {image: {slot: image, rule: img}, value: {slot: value, rule: port}}, actor: a}
`
	swapped := strings.Replace(base,
		"args: {image: {slot: image, rule: img}, value: {slot: value, rule: port}}",
		"args: {image: {slot: image, rule: port}, value: {slot: value, rule: img}}", 1)

	a, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(swapped))
	if err != nil {
		t.Fatal(err)
	}
	if a.SemanticHash == b.SemanticHash {
		t.Error("which rule clears which argument must change the policy identity")
	}
	if a.Recipe.Steps[2].ArgRules["image"].RuleID != "img" {
		t.Errorf("each argument must bind its OWN rule: %+v", a.Recipe.Steps[2].ArgRules)
	}
	if a.Recipe.Steps[2].ArgRules["value"].RuleID != "port" {
		t.Errorf("each argument must bind its OWN rule: %+v", a.Recipe.Steps[2].ArgRules)
	}
}

// An argument missing its rule is rejected: an argument nobody wrote a rule for is not
// thereby permitted.
func TestInvokeArgumentWithoutRuleRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: ns}}, actor: a}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("an argument with no rule must be rejected")
	}
}

// The old single-rule form is no longer accepted: a step-level `rule` on an invoke is an
// error, not silently ignored.
func TestInvokeStepLevelRuleRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules: {ok: {kind: set_membership, set: ["dev"]}}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: i, kind: invoke, tool: t, args: {node: {slot: ns, rule: ok}}, rule: ok, actor: a}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("a step-level rule on an invoke must be rejected")
	}
}
