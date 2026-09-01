package recipe

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// the Planning/09 worked recipe, verbatim.
const fixture = `recipe: cdn_remediation
version: 1

rules:
  routes.all:
    kind: set_membership
    set: ["class:regional_fallback", "class:edge_only", "class:transcontinental"]
  routes.auto_approvable:
    kind: set_membership
    set: ["class:regional_fallback", "class:edge_only"]
  cache.approved_classes:
    kind: set_membership
    set: ["class:release_prewarm"]

steps:
  - id: propose_plan
    kind: propose
    out: plan

  - id: choose_path
    kind: branch
    in: plan
    cases:
      - rule: routes.all
        goto: check_route
      - rule: cache.approved_classes
        goto: apply_prefetch
    default: log_only

  - id: check_route
    kind: gate
    in: plan
    rule: routes.auto_approvable
    on_fail: escalate

  - id: apply_route
    kind: sink
    in: plan
    field: aws_route_apply.args.route
    sensitivity: authoritative
    rule: routes.auto_approvable
    actor: "policy:network_remediation"
    goto: log_only

  - id: apply_prefetch
    kind: sink
    in: plan
    field: edge_cache_prefetch.args.plan
    sensitivity: authoritative
    rule: cache.approved_classes
    actor: "policy:cache_budget"

  - id: log_only
    kind: sink
    in: plan
    field: log.plan
    sensitivity: benign
`

// minimal valid recipe, base for poison variants.
const skeleton = `recipe: r
version: 1
steps:
  - id: s0
    kind: propose
    out: p
  - id: s1
    kind: sink
    in: p
    field: log.x
    sensitivity: benign
`

func TestRecipeParseFixture(t *testing.T) {
	p, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	if _, w, derr := ParseDraft([]byte(fixture)); derr != nil || len(w) != 0 {
		t.Fatalf("fixture draft: warnings=%v err=%v", w, derr)
	}
	if p.Header.Name != "cdn_remediation" || p.Header.Version != 1 {
		t.Errorf("header: %+v", p.Header)
	}
	if len(p.Rules) != 3 {
		t.Errorf("registry: want 3 rules, got %d", len(p.Rules))
	}
	if len(p.ArtifactHash) != 64 || len(p.SemanticHash) != 64 {
		t.Errorf("hashes: %q %q", p.ArtifactHash, p.SemanticHash)
	}

	st := p.Recipe.Steps
	if len(st) != 6 {
		t.Fatalf("steps: want 6, got %d", len(st))
	}
	wantIds := []string{"propose_plan", "choose_path", "check_route", "apply_route", "apply_prefetch", "log_only"}
	wantKinds := []stag.NodeKind{stag.NodePropose, stag.NodeBranch, stag.NodeGate, stag.NodeSink, stag.NodeSink, stag.NodeSink}
	for i := range st {
		if st[i].Id != wantIds[i] || st[i].Kind != wantKinds[i] {
			t.Errorf("step %d: id=%q kind=%v", i, st[i].Id, st[i].Kind)
		}
	}
	br := st[1]
	if len(br.Cases) != 2 || br.Cases[0].Goto != "check_route" || br.Cases[1].Goto != "apply_prefetch" ||
		br.Default != "log_only" || br.In != "plan" {
		t.Errorf("branch: %+v", br)
	}
	if br.Cases[0].Rule == nil || len(br.Cases[0].Rule.Set) != 3 {
		t.Errorf("branch case rule not bound: %+v", br.Cases[0].Rule)
	}
	g := st[2]
	if !g.Escalate || g.Rule == nil || len(g.Rule.Set) != 2 || g.In != "plan" {
		t.Errorf("gate: %+v", g)
	}
	rt := st[3]
	if rt.RuleID != "routes.auto_approvable" || rt.Rule == nil || rt.Sensitivity != stag.SinkAuthoritative ||
		rt.Actor != "policy:network_remediation" || rt.Field != "aws_route_apply.args.route" || rt.Goto != "log_only" {
		t.Errorf("route sink: %+v", rt)
	}
	if reg, ok := p.Rules["routes.auto_approvable"]; !ok || !reflect.DeepEqual(reg, *rt.Rule) {
		t.Errorf("rule id and rule body not from one registry entry")
	}
	if st[5].Sensitivity != stag.SinkBenign || st[5].Field != "log.plan" {
		t.Errorf("log sink: %+v", st[5])
	}

	// the whole product: YAML to verdicts, events bound to the semantic hash.
	r1 := stag.Eval(p.Recipe, "class:regional_fallback", p.SemanticHash)
	if r1.Verdict != stag.Allow || r1.Fault != "" || len(r1.Events) != 1 ||
		r1.Events[0].TargetField != "aws_route_apply.args.route" ||
		r1.Events[0].AuthorizingRule != "routes.auto_approvable" ||
		r1.Events[0].RecipeHash != p.SemanticHash || r1.Events[0].Ordering != 3 {
		t.Errorf("path1: %+v", r1)
	}
	r2 := stag.Eval(p.Recipe, "class:release_prewarm", p.SemanticHash)
	if r2.Verdict != stag.Allow || len(r2.Events) != 1 || len(r2.Gates) != 0 ||
		r2.Events[0].TargetField != "edge_cache_prefetch.args.plan" {
		t.Errorf("path2: %+v", r2)
	}
	r3 := stag.Eval(p.Recipe, "class:transcontinental", p.SemanticHash)
	if r3.Verdict != stag.Escalate || len(r3.Events) != 0 || len(r3.Sinks) != 0 ||
		len(r3.Gates) != 1 || r3.Gates[0].Passed {
		t.Errorf("path3: %+v", r3)
	}
	r4 := stag.Eval(p.Recipe, "rm -rf /", p.SemanticHash)
	if r4.Verdict != stag.Allow || len(r4.Events) != 0 || len(r4.Gates) != 0 ||
		len(r4.Sinks) != 1 || r4.Sinks[0].Sink != stag.SinkBenign {
		t.Errorf("path4: %+v", r4)
	}
	for _, r := range []stag.EvalResult{r1, r2, r3, r4} {
		if r.Fault != "" {
			t.Errorf("a parsed recipe tripped a kernel backstop: %+v", r)
		}
	}
}

func TestRecipeParseRejections(t *testing.T) {
	// byte-level prelims
	raw := [][2]string{}
	_ = raw
	byteCases := []struct {
		name string
		src  []byte
		want string
	}{
		{"oversize", append([]byte("recipe: r\n# "), make([]byte, 70000)...), "too large"},
		{"utf8 bom", append([]byte{0xEF, 0xBB, 0xBF}, []byte(skeleton)...), "byte-order mark"},
		{"utf16 bom", []byte{0xFF, 0xFE, 'r', 0}, "byte-order mark"},
		{"nul byte", []byte("recipe: r\x00\nversion: 1\n"), "NUL"},
		{"invalid utf8", []byte("recipe: r\xff\xfe\nversion: 1\n"), "invalid UTF-8"},
	}
	for _, c := range byteCases {
		if _, err := Parse(c.src); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want substring %q", c.name, err, c.want)
		}
	}

	poison := func(old, new string) string { return strings.Replace(fixture, old, new, 1) }
	cases := []struct {
		name string
		src  string
		want string
	}{
		// document
		{"two documents", skeleton + "---\nrecipe: r2\nversion: 1\nsteps: [{id: s0, kind: propose, out: p}]\n", "one document"},
		{"empty document", "\n", "empty document"},
		{"root sequence", "- a\n- b\n", "mapping"},
		// hygiene
		{"anchor", strings.Replace(skeleton, "out: p", "out: &a p", 1), "anchor"},
		{"alias", strings.Replace(strings.Replace(skeleton, "out: p", "out: &a p", 1), "in: p", "in: *a", 1), "alias"},
		{"merge key", strings.Replace(skeleton, "    kind: propose\n", "    kind: propose\n    <<: {x: 1}\n", 1), "merge"},
		{"duplicate key", strings.Replace(skeleton, "    kind: propose\n", "    kind: propose\n    kind: propose\n", 1), "duplicate key"},
		{"unknown top key", "junk: 1\n" + skeleton, "unknown key"},
		{"depth bomb", "recipe: r\nversion: 1\nsteps: " + strings.Repeat("[", 40) + strings.Repeat("]", 40) + "\n", "depth"},
		{"node bomb", "recipe: r\nversion: 1\nsteps: [" + strings.Repeat("a,", 10001) + "]\n", "too many nodes"},
		// tags and scalars
		{"quoted version", poison("version: 1", `version: "1"`), "canonical integer"},
		{"version 2", poison("version: 1", "version: 2"), "version must be 1"},
		{"binary tag", strings.Replace(skeleton, "field: log.x", "field: !!binary aGk=", 1), "quoted"},
		{"timestamp origin", "recipe: r\nversion: 1\ningredients:\n  a:\n    origin: 2026-07-01\n    trust: untrusted\nsteps:\n  - id: s0\n    kind: sink\n    in: a\n    field: log.x\n    sensitivity: benign\n", "quoted"},
		{"unquoted bool word", strings.Replace(skeleton, "field: log.x", "field: on", 1), "quoted"},
		{"unquoted set member", poison(`set: ["class:release_prewarm"]`, "set: [class_release_prewarm]"), "quoted"},
		// names
		{"uppercase name", poison("recipe: cdn_remediation", "recipe: CDN"), "name"},
		{"long id", strings.Replace(skeleton, "id: s0", "id: "+strings.Repeat("x", 65), 1), "name"},
		{"empty rule segment", poison("routes.all:", "routes..all:"), "rule id"},
		// ingredients
		{"authored value", "recipe: r\nversion: 1\ningredients:\n  a:\n    origin: x\n    trust: untrusted\n    value: sneak\nsteps:\n  - id: s0\n    kind: sink\n    in: a\n    field: log.x\n    sensitivity: benign\n", "unknown key"},
		{"unknown trust", "recipe: r\nversion: 1\ningredients:\n  a:\n    origin: x\n    trust: trusted\nsteps:\n  - id: s0\n    kind: sink\n    in: a\n    field: log.x\n    sensitivity: benign\n", "trust class"},
		// rules registry
		{"old kind spelling", poison("kind: set_membership", "kind: set"), "rule kind"},
		{"missing set", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: set_membership"), "requires set"},
		{"empty set", poison(`set: ["class:release_prewarm"]`, "set: []"), "empty set"},
		{"duplicate set member", poison(`set: ["class:release_prewarm"]`, `set: ["class:release_prewarm", "class:release_prewarm"]`), "duplicate set member"},
		{"empty signed", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: signed_equality\n    signed: \"\""), "empty signed"},
		{"min gt max", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 9\n    max: 1"), "min"},
		{"cross-field forbidden", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 1\n    max: 9\n    set: [\"x\"]"), "not legal"},
		{"non-canonical octal", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 07\n    max: 9"), "canonical integer"},
		{"non-canonical plus", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: +5\n    max: 9"), "canonical integer"},
		{"non-canonical hex", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 0x1F\n    max: 99"), "canonical integer"},
		{"non-canonical underscore", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 1_000\n    max: 9999"), "canonical integer"},
		{"float min", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 5.5\n    max: 9"), "canonical integer"},
		{"exponent min", poison("    kind: set_membership\n    set: [\"class:release_prewarm\"]", "    kind: numeric_range\n    min: 1e3\n    max: 9999"), "canonical integer"},
		// steps: schema
		{"missing id", strings.Replace(skeleton, "  - id: s0\n", "  - ", 1), "id"},
		{"duplicate id", strings.Replace(skeleton, "id: s1", "id: s0", 1), "duplicate id"},
		{"foreach missing in", strings.Replace(skeleton, "kind: propose\n    out: p", "kind: foreach", 1), "requires in"},
		{"exit with illegal key", strings.Replace(skeleton, "kind: propose\n    out: p", "kind: exit\n    in: p", 1), "not legal"},
		{"unknown kind", strings.Replace(skeleton, "kind: propose", "kind: frobnicate", 1), "unknown kind"},
		{"out on sink", strings.Replace(skeleton, "field: log.x", "field: log.x\n    out: q", 1), "not legal"},
		{"goto on gate", poison("    rule: routes.auto_approvable\n    on_fail: escalate", "    rule: routes.auto_approvable\n    goto: log_only"), "not legal"},
		{"rule on benign sink", strings.Replace(fixture, "field: log.plan\n    sensitivity: benign", "field: log.plan\n    sensitivity: benign\n    rule: routes.all\n    actor: \"a\"", 1), "dead policy"},
		{"rule without actor", poison("    rule: routes.auto_approvable\n    actor: \"policy:network_remediation\"\n", "    rule: routes.auto_approvable\n"), "actor"},
		// graph lint
		{"undeclared slot", strings.Replace(skeleton, "in: p", "in: nope", 1), "undeclared slot"},
		{"use before declare", "recipe: r\nversion: 1\nsteps:\n  - id: s0\n    kind: sink\n    in: p\n    field: log.x\n    sensitivity: benign\n  - id: s1\n    kind: propose\n    out: p\n", "undeclared slot"},
		{"unregistered rule", poison("rule: routes.auto_approvable\n    on_fail: escalate", "rule: routes.nope\n    on_fail: escalate"), "unregistered rule"},
		{"dangling goto", poison("goto: log_only", "goto: nowhere"), "unknown id"},
		{"backward goto", poison("goto: log_only", "goto: propose_plan"), "backward"},
		{"missing default", poison("    default: log_only\n", ""), "default"},
		{"empty cases", poison("    cases:\n      - rule: routes.all\n        goto: check_route\n      - rule: cache.approved_classes\n        goto: apply_prefetch\n", "    cases: []\n"), "cases"},
		{"duplicate out", strings.Replace(skeleton, "id: s1\n    kind: sink\n    in: p\n    field: log.x\n    sensitivity: benign", "id: s1\n    kind: propose\n    out: p", 1), "duplicate out"},
		{"out collides ingredient", "recipe: r\nversion: 1\ningredients:\n  p:\n    origin: x\n    trust: untrusted\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: s1\n    kind: sink\n    in: p\n    field: log.x\n    sensitivity: benign\n", "duplicate out"},
		{"duplicate field", poison("field: edge_cache_prefetch.args.plan", "field: aws_route_apply.args.route"), "duplicate field"},
		{"guaranteed deny", strings.Replace(skeleton, "sensitivity: benign", "sensitivity: authoritative", 1), "guaranteed deny"},
		{"unreachable step", "recipe: r\nversion: 1\nrules:\n  rr:\n    kind: set_membership\n    set: [\"x\"]\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: br\n    kind: branch\n    in: p\n    cases:\n      - rule: rr\n        goto: z\n    default: z\n  - id: dead\n    kind: sink\n    in: p\n    field: log.d\n    sensitivity: benign\n  - id: z\n    kind: sink\n    in: p\n    field: log.z\n    sensitivity: benign\n", "unreachable"},
		{"edge into guarded segment", "recipe: r\nversion: 1\nrules:\n  rr:\n    kind: set_membership\n    set: [\"x\"]\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: br\n    kind: branch\n    in: p\n    cases:\n      - rule: rr\n        goto: milestone\n    default: g\n  - id: g\n    kind: gate\n    in: p\n    rule: rr\n  - id: milestone\n    kind: sink\n    in: p\n    field: f.x\n    sensitivity: authoritative\n    rule: rr\n    actor: \"a\"\n", "guarded segment"},
		// U4-adversarial: a branch can skip a propose whose out-slot a later step reads
		{"skip-path slot", "recipe: r\nversion: 1\nrules:\n  rr:\n    kind: set_membership\n    set: [\"go\"]\nsteps:\n  - id: s0\n    kind: propose\n    out: a\n  - id: b1\n    kind: branch\n    in: a\n    cases:\n      - rule: rr\n        goto: mkb\n    default: useb\n  - id: mkb\n    kind: propose\n    out: b\n  - id: useb\n    kind: branch\n    in: b\n    cases:\n      - rule: rr\n        goto: sa\n    default: sb\n  - id: sa\n    kind: sink\n    in: a\n    field: f.a\n    sensitivity: benign\n  - id: sb\n    kind: sink\n    in: a\n    field: f.b\n    sensitivity: benign\n", "not defined on every path"},
		// U4-adversarial: anchor on a mapping KEY (not just a value)
		{"key anchor", "&x recipe: r\nversion: 1\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: s1\n    kind: sink\n    in: p\n    field: log.x\n    sensitivity: benign\n", "anchor"},
		// U4-adversarial: custom tag on a collection node
		{"collection tag", poison(`set: ["class:release_prewarm"]`, `set: !custom ["class:release_prewarm"]`), "custom tag"},
		// U4-adversarial: control byte smuggled into a value via double-quote escape
		{"control byte value", strings.Replace(skeleton, "field: log.x", `field: "log.\tx"`, 1), "control character"},
		// teaching rejections
		{"when", strings.Replace(skeleton, "    kind: propose\n", "    kind: propose\n    when: x\n", 1), "branch kind"},
		{"loop", strings.Replace(skeleton, "    kind: propose\n", "    kind: propose\n    loop: x\n", 1), "foreach"},
		{"register", strings.Replace(skeleton, "    kind: propose\n", "    kind: propose\n    register: x\n", 1), "propose"},
		{"vars", "vars: {x: 1}\n" + skeleton, "ingredients"},
		{"on instead of in", poison("    in: plan\n    cases:", "    on: plan\n    cases:"), "use in:"},
		{"templating", strings.Replace(skeleton, "field: log.x", `field: "{{ item }}"`, 1), "templating"},
	}
	for _, c := range cases {
		p, err := Parse([]byte(c.src))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want substring %q", c.name, err, c.want)
		}
		if !reflect.DeepEqual(p, Parsed{}) {
			t.Errorf("%s: rejected input leaked a non-zero Parsed (reject-before-hash)", c.name)
		}
	}

	// exit is now a real terminal kind (implemented for composition); it parses. An unknown
	// kind is still rejected as unknown — no recognized-but-rejected sentinel remains.
	exitRecipe := "recipe: r\nversion: 1\nsteps:\n  - id: s0\n    kind: propose\n    out: p\n  - id: done\n    kind: exit\n"
	if _, err := Parse([]byte(exitRecipe)); err != nil {
		t.Errorf("exit must parse as a terminal: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(skeleton, "kind: propose", "kind: frobnicate", 1))); err == nil {
		t.Errorf("unknown kind must be rejected")
	}
}

func TestRecipeParseModes(t *testing.T) {
	dead := `recipe: r
version: 1
ingredients:
  spare:
    origin: x
    trust: untrusted
rules:
  used.rule:
    kind: set_membership
    set: ["ok"]
  dead.rule:
    kind: set_membership
    set: ["never"]
steps:
  - id: s0
    kind: propose
    out: p
  - id: s1
    kind: sink
    in: p
    field: act.x
    sensitivity: authoritative
    rule: used.rule
    actor: "a"
`
	_, w, err := ParseDraft([]byte(dead))
	if err != nil {
		t.Fatalf("draft must succeed: %v", err)
	}
	joined := strings.Join(w, "; ")
	if len(w) != 2 || !strings.Contains(joined, "unused ingredient") || !strings.Contains(joined, "unreferenced rule") {
		t.Errorf("draft warnings: %v", w)
	}
	if _, err := Parse([]byte(dead)); err == nil {
		t.Errorf("strict must reject dead declarations")
	}

	emptyMember := strings.Replace(dead, `set: ["ok"]`, `set: ["", "ok"]`, 1)
	emptyMember = strings.Replace(emptyMember, "ingredients:\n  spare:\n    origin: x\n    trust: untrusted\n", "", 1)
	emptyMember = strings.Replace(emptyMember, "  dead.rule:\n    kind: set_membership\n    set: [\"never\"]\n", "", 1)
	_, w2, err := ParseDraft([]byte(emptyMember))
	if err != nil || len(w2) != 1 || !strings.Contains(w2[0], "empty string") {
		t.Errorf("empty member: warnings=%v err=%v", w2, err)
	}
	if _, err := Parse([]byte(emptyMember)); err == nil {
		t.Errorf("strict must reject empty-string set member")
	}
}

func TestRecipeParseHashes(t *testing.T) {
	p1, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(fixture))
	if p1.ArtifactHash != hex.EncodeToString(sum[:]) {
		t.Errorf("artifact hash is not sha256 of raw bytes")
	}

	// comments move the artifact hash, never the semantic hash
	commented := "# a comment\n" + fixture
	p2, err := Parse([]byte(commented))
	if err != nil {
		t.Fatal(err)
	}
	if p2.SemanticHash != p1.SemanticHash {
		t.Errorf("comment changed the semantic hash")
	}
	if p2.ArtifactHash == p1.ArtifactHash {
		t.Errorf("comment did not change the artifact hash")
	}

	// set member order is canonicalized away
	reordered := strings.Replace(fixture,
		`set: ["class:regional_fallback", "class:edge_only", "class:transcontinental"]`,
		`set: ["class:transcontinental", "class:edge_only", "class:regional_fallback"]`, 1)
	p3, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if p3.SemanticHash != p1.SemanticHash {
		t.Errorf("set order changed the semantic hash")
	}

	// real semantic edits change it
	for _, edit := range [][2]string{
		{`"class:edge_only"]`, `"class:edge_only2"]`},
		{"on_fail: escalate", "on_fail: deny"},
		{`actor: "policy:cache_budget"`, `actor: "policy:other"`},
	} {
		pe, err := Parse([]byte(strings.Replace(fixture, edit[0], edit[1], 1)))
		if err != nil {
			t.Fatalf("edit %q: %v", edit[1], err)
		}
		if pe.SemanticHash == p1.SemanticHash {
			t.Errorf("semantic edit %q did not change the semantic hash", edit[1])
		}
	}

	// determinism
	p4, err := Parse([]byte(fixture))
	if err != nil || !reflect.DeepEqual(p1, p4) {
		t.Errorf("determinism: parses differ (%v)", err)
	}
}

func FuzzRecipeParse(f *testing.F) {
	f.Add([]byte(fixture))
	f.Add([]byte(skeleton))
	f.Add([]byte("recipe: r\nversion: 1\nsteps: [" + strings.Repeat("a,", 50) + "]\n"))
	f.Add([]byte("&a [*a, *a]\n"))
	f.Add([]byte("recipe: r\n---\nrecipe: q\n"))
	f.Add(append([]byte{0xEF, 0xBB, 0xBF}, []byte(skeleton)...))
	f.Add([]byte(strings.Replace(fixture, "version: 1", "version: 0x1", 1)))
	f.Fuzz(func(t *testing.T, src []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC escaped Parse: %v", r)
			}
		}()
		p, err := Parse(src)
		if err != nil {
			if !reflect.DeepEqual(p, Parsed{}) {
				t.Errorf("rejected input leaked a non-zero Parsed")
			}
			return
		}
		// accepted: deterministic, hashes well-formed, draft-clean, kernel-safe
		p2, err2 := Parse(src)
		if err2 != nil || !reflect.DeepEqual(p, p2) {
			t.Errorf("DETERMINISM: second parse differs (%v)", err2)
		}
		sum := sha256.Sum256(src)
		if p.ArtifactHash != hex.EncodeToString(sum[:]) {
			t.Errorf("artifact hash mismatch")
		}
		if len(p.SemanticHash) != 64 || p.Header.Version != 1 || len(p.Recipe.Steps) == 0 {
			t.Errorf("accepted parse ill-formed: %+v", p.Header)
		}
		if _, w, derr := ParseDraft(src); derr != nil || len(w) != 0 {
			t.Errorf("strict acceptance implies draft-clean: %v %v", w, derr)
		}
		// an ACCEPTED recipe never trips a kernel Fault, on ANY proposal (the
		// definite-assignment lint subsumes the kernel's structural backstops).
		for _, prop := range []string{"class:regional_fallback", "class:release_prewarm", "class:transcontinental", "go", "", "rm -rf /"} {
			if res := stag.Eval(p.Recipe, prop, p.SemanticHash); res.Fault != "" {
				t.Errorf("parsed recipe faulted on proposal %q: %q", prop, res.Fault)
			}
		}
	})
}
