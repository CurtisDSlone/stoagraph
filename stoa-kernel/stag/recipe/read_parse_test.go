package recipe

import (
	"strings"
	"testing"
)

const readSrc = `
recipe: maint_brief
version: 1
rules:
  topic.allowed: {kind: set_membership, set: ["drain", "rollout"]}
  node.worker:   {kind: set_membership, set: ["kind-worker"]}
steps:
  - {id: p_topic, kind: propose, out: topic}
  - {id: p_node,  kind: propose, out: node}
  - {id: brief, kind: read, provider: runbooks, query: {slot: topic, rule: topic.allowed}}
  - {id: act, kind: sink, in: node, field: k8s.act, sensitivity: authoritative,
     rule: node.worker, actor: "policy:maint"}
`

func TestReadParses(t *testing.T) {
	p, err := Parse([]byte(readSrc))
	if err != nil {
		t.Fatalf("a valid read recipe must parse: %v", err)
	}
	st := p.Recipe.Steps[2]
	if st.Provider != "runbooks" {
		t.Errorf("provider: %q", st.Provider)
	}
	if st.QuerySlot != "topic" || st.QueryRuleID != "topic.allowed" || st.QueryRule == nil {
		t.Errorf("the query must compile with its slot and rule: %+v", st)
	}
}

// WHICH source and WHAT may be asked are both part of the policy's identity.
func TestReadRidesInSemanticHash(t *testing.T) {
	base, err := Parse([]byte(readSrc))
	if err != nil {
		t.Fatal(err)
	}
	// a different SOURCE, gated identically
	other, err := Parse([]byte(strings.Replace(readSrc, "provider: runbooks", "provider: incidents", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if other.SemanticHash == base.SemanticHash {
		t.Error("reading a different source must change the policy identity")
	}

	// and a WIDER question of the same source. Both rules stay referenced, so this isolates
	// the query rule rather than incidentally orphaning one.
	const narrow = `
recipe: q
version: 1
rules:
  narrow: {kind: set_membership, set: ["drain"]}
  wide:   {kind: set_membership, set: ["drain", "anything"]}
steps:
  - {id: p, kind: propose, out: t}
  - {id: rd, kind: read, provider: runbooks, query: {slot: t, rule: narrow}}
  - {id: s, kind: sink, in: t, field: f, sensitivity: authoritative, rule: wide, actor: x}
`
	pn, err := Parse([]byte(narrow))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := Parse([]byte(strings.Replace(
		strings.Replace(narrow, "rule: narrow}}", "rule: wide}}", 1),
		"rule: wide, actor", "rule: narrow, actor", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if pn.SemanticHash == pw.SemanticHash {
		t.Error("widening WHAT may be asked must change the policy identity")
	}
}

// Fail closed at the boundary.
func TestReadRejectsMalformed(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no provider", strings.Replace(readSrc, "provider: runbooks, ", "", 1)},
		{"no query", strings.Replace(readSrc, ", query: {slot: topic, rule: topic.allowed}", "", 1)},
		{"query missing rule", strings.Replace(readSrc, "query: {slot: topic, rule: topic.allowed}", "query: {slot: topic}", 1)},
		{"query missing slot", strings.Replace(readSrc, "query: {slot: topic, rule: topic.allowed}", "query: {rule: topic.allowed}", 1)},
		{"unknown query rule", strings.Replace(readSrc, "rule: topic.allowed}}", "rule: nope}}", 1)},
		{"undeclared query slot", strings.Replace(readSrc, "query: {slot: topic,", "query: {slot: undeclared,", 1)},
		{"illegal key", strings.Replace(readSrc, "provider: runbooks,", "provider: runbooks, sensitivity: authoritative,", 1)},
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c.src)); err == nil {
			t.Errorf("%s: must be rejected", c.name)
		}
	}
}

// A read inside a foreach is refused: an attacker-chosen list length would multiply the
// outbound queries, which is the exfiltration channel the bound exists to close.
func TestReadInsideForeachRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules:
  ok: {kind: set_membership, set: ["a"]}
steps:
  - {id: p, kind: propose, out: list}
  - {id: fe, kind: foreach, in: list, as: item}
  - {id: rd, kind: read, provider: x, query: {slot: item, rule: ok}}
`
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("a read inside a foreach must be rejected")
	}
	if !strings.Contains(err.Error(), "foreach") {
		t.Errorf("the error must name the construct it refuses: %v", err)
	}
}

// Two reads of the SAME provider are refused: one source, one step, so the audit cannot show two
// reads it cannot tell apart.
func TestDuplicateProviderRejected(t *testing.T) {
	src := `
recipe: r
version: 1
rules:
  ok: {kind: set_membership, set: ["a"]}
steps:
  - {id: p, kind: propose, out: t}
  - {id: r1, kind: read, provider: runbooks, query: {slot: t, rule: ok}}
  - {id: r2, kind: read, provider: runbooks, query: {slot: t, rule: ok}}
`
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("two reads of one provider must be rejected")
	}
}
