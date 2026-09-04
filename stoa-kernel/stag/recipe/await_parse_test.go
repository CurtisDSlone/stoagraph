package recipe

import (
	"strings"
	"testing"
)

const awaitSrc = `
recipe: drain_seq
version: 1
rules:
  node.worker: {kind: set_membership, set: ["kind-worker"]}
  pods.none:   {kind: set_membership, set: ["none"]}
steps:
  - {id: p, kind: propose, out: node}
  - {id: settle, kind: await, tool: k8s__pods_on_node,
     args: {node: {slot: node, rule: node.worker}},
     until: pods.none, attempts: 6, every_ms: 5000, actor: "policy:drain"}
`

func TestAwaitParses(t *testing.T) {
	p, err := Parse([]byte(awaitSrc))
	if err != nil {
		t.Fatalf("a valid await recipe must parse: %v", err)
	}
	st := p.Recipe.Steps[1]
	if st.Tool != "k8s__pods_on_node" {
		t.Errorf("tool: %q", st.Tool)
	}
	if st.Until == nil || st.UntilID != "pods.none" {
		t.Errorf("the until-condition must compile: %+v", st)
	}
	if st.Attempts != 6 || st.DelayMS != 5000 {
		t.Errorf("bounds: attempts=%d delay=%d", st.Attempts, st.DelayMS)
	}
}

// The condition and the bounds ride in the SEMANTIC hash: how long a policy is willing to wait,
// and for what, is part of what the policy IS.
func TestAwaitBoundsRideInSemanticHash(t *testing.T) {
	base, err := Parse([]byte(awaitSrc))
	if err != nil {
		t.Fatal(err)
	}
	for _, alt := range []string{
		strings.Replace(awaitSrc, "attempts: 6", "attempts: 3", 1),
		strings.Replace(awaitSrc, "every_ms: 5000", "every_ms: 1000", 1),
		// a different tool polled: same rules, different policy
		strings.Replace(awaitSrc, "tool: k8s__pods_on_node", "tool: k8s__get_workload", 1),
	} {
		p, err := Parse([]byte(alt))
		if err != nil {
			t.Fatal(err)
		}
		if p.SemanticHash == base.SemanticHash {
			t.Error("changing the condition or the bounds must change the policy identity")
		}
	}
}

// Fail closed at the boundary on every missing or out-of-range part.
func TestAwaitRejectsMalformed(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no until", strings.Replace(awaitSrc, "until: pods.none, ", "", 1)},
		{"unknown until rule", strings.Replace(awaitSrc, "until: pods.none", "until: nope", 1)},
		{"no attempts", strings.Replace(awaitSrc, "attempts: 6, ", "", 1)},
		{"no interval", strings.Replace(awaitSrc, "every_ms: 5000, ", "", 1)},
		{"attempts over cap", strings.Replace(awaitSrc, "attempts: 6", "attempts: 999", 1)},
		{"interval over cap", strings.Replace(awaitSrc, "every_ms: 5000", "every_ms: 99999999", 1)},
		{"zero attempts", strings.Replace(awaitSrc, "attempts: 6", "attempts: 0", 1)},
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c.src)); err == nil {
			t.Errorf("%s: must be rejected", c.name)
		}
	}
}

// An `until` on an INVOKE is rejected: an invoke is one call, and a condition there would be
// dead policy — the same discipline that refuses a rule on a benign sink.
func TestUntilOnInvokeRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules:
  ok: {kind: set_membership, set: ["x"]}
steps:
  - {id: p, kind: propose, out: v}
  - {id: i, kind: invoke, tool: t, args: {a: {slot: v, rule: ok}}, until: ok, actor: a}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("an until-condition on an invoke must be rejected")
	}
}

// The bounds a recipe may ask for are the KERNEL's, and the linter says so at author time
// rather than leaving it to a runtime fault.
func TestAwaitCapErrorNamesTheLimit(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(awaitSrc, "attempts: 6", "attempts: 999", 1)))
	if err == nil {
		t.Fatal("over-cap attempts must be rejected")
	}
	if !strings.Contains(err.Error(), "attempts") {
		t.Errorf("the error must name what was exceeded: %v", err)
	}
}
