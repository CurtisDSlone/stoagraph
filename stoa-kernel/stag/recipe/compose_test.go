package recipe

import (
	"fmt"
	"strings"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// child sub-recipe, SEALED (ends in exit): gates a target against the escalation set.
const childSrc = `recipe: escalate_policy
version: 1
rules:
  esc.allowed:
    kind: set_membership
    set: ["delete_all", "shutdown"]
steps:
  - id: propose_target
    kind: propose
    out: target
  - id: apply
    kind: sink
    in: target
    field: mcp.escalate.action
    sensitivity: authoritative
    rule: esc.allowed
    actor: "policy:escalation"
  - id: done
    kind: exit
`

// parent, SEALED: routes normal actions to a normal sink and escalations INTO the child
// sub-recipe (goto_recipe). route.esc is a superset of esc.allowed so a routed-but-
// disallowed value ("wipe") reaches the child and is denied there.
const parentSrc = `recipe: router
version: 1
rules:
  route.esc:
    kind: set_membership
    set: ["delete_all", "shutdown", "wipe"]
  route.normal:
    kind: set_membership
    set: ["restart", "scale"]
steps:
  - id: propose_action
    kind: propose
    out: action
  - id: route
    kind: branch
    in: action
    cases:
      - rule: route.normal
        goto: normal_sink
      - rule: route.esc
        goto_recipe: escalate_policy
    default: noop
  - id: normal_sink
    kind: sink
    in: action
    field: mcp.exec.normal
    sensitivity: authoritative
    rule: route.normal
    actor: "policy:normal"
  - id: noop
    kind: exit
`

func mapResolver(m map[string]string) Resolver {
	return func(name string) ([]byte, error) {
		s, ok := m[name]
		if !ok {
			return nil, fmt.Errorf("no such recipe %q", name)
		}
		return []byte(s), nil
	}
}

var stdResolve = mapResolver(map[string]string{"escalate_policy": childSrc})

// eventFields returns the TargetField of every release event (which path crossed).
func eventFields(r stag.EvalResult) []string {
	var out []string
	for _, e := range r.Events {
		out = append(out, e.TargetField)
	}
	return out
}

func TestComposeInlinesChild(t *testing.T) {
	p, w, err := Compose([]byte(parentSrc), stdResolve)
	if err != nil {
		t.Fatalf("compose: %v (warns %v)", err, w)
	}
	// parent (4) + inlined child (3) steps, child namespaced.
	if len(p.Recipe.Steps) != 7 {
		t.Fatalf("composed step count = %d, want 7", len(p.Recipe.Steps))
	}
	var sawNamespaced bool
	for _, st := range p.Recipe.Steps {
		if strings.HasPrefix(st.Id, "s0_") {
			sawNamespaced = true
		}
	}
	if !sawNamespaced {
		t.Fatalf("no namespaced child step found: %+v", p.Recipe.Steps)
	}

	// normal path: gated by the parent, child NOT run.
	rn := stag.Eval(p.Recipe, "restart", p.SemanticHash)
	if rn.Verdict != stag.Allow || len(rn.Events) != 1 || eventFields(rn)[0] != "mcp.exec.normal" {
		t.Errorf("normal: verdict=%v events=%v", rn.Verdict, eventFields(rn))
	}
	// escalation allowed: routes INTO the child, child clears it (escalate field).
	re := stag.Eval(p.Recipe, "delete_all", p.SemanticHash)
	if re.Verdict != stag.Allow || len(re.Events) != 1 || eventFields(re)[0] != "mcp.escalate.action" {
		t.Errorf("escalate-allow: verdict=%v events=%v", re.Verdict, eventFields(re))
	}
	// escalation routed but DISALLOWED by the child: denied inside the inlined sub-recipe.
	rw := stag.Eval(p.Recipe, "wipe", p.SemanticHash)
	if rw.Verdict != stag.Deny || len(rw.Events) != 0 {
		t.Errorf("escalate-deny: verdict=%v events=%v", rw.Verdict, eventFields(rw))
	}
	// unrouted: default exit, no action.
	rd := stag.Eval(p.Recipe, "nonsense", p.SemanticHash)
	if rd.Verdict != stag.Allow || len(rd.Events) != 0 {
		t.Errorf("default: verdict=%v events=%v", rd.Verdict, eventFields(rd))
	}
}

// a parent that references the child ONCE, on the default path (default_recipe).
const defaultParentSrc = `recipe: router
version: 1
rules:
  route.normal:
    kind: set_membership
    set: ["restart"]
steps:
  - id: propose_action
    kind: propose
    out: action
  - id: route
    kind: branch
    in: action
    cases:
      - rule: route.normal
        goto: normal_sink
    default_recipe: escalate_policy
  - id: normal_sink
    kind: sink
    in: action
    field: mcp.exec.normal
    sensitivity: authoritative
    rule: route.normal
    actor: "policy:normal"
  - id: noop
    kind: exit
`

func TestComposeDefaultRecipe(t *testing.T) {
	p, _, err := Compose([]byte(defaultParentSrc), stdResolve)
	if err != nil {
		t.Fatalf("compose default_recipe: %v", err)
	}
	// a value matching no case routes into the inlined child on the default path.
	re := stag.Eval(p.Recipe, "shutdown", p.SemanticHash)
	if re.Verdict != stag.Allow || len(re.Events) != 1 || eventFields(re)[0] != "mcp.escalate.action" {
		t.Errorf("default_recipe route: verdict=%v events=%v", re.Verdict, eventFields(re))
	}
	// the normal case still gates in the parent.
	rn := stag.Eval(p.Recipe, "restart", p.SemanticHash)
	if rn.Verdict != stag.Allow || len(rn.Events) != 1 || eventFields(rn)[0] != "mcp.exec.normal" {
		t.Errorf("normal case: verdict=%v events=%v", rn.Verdict, eventFields(rn))
	}
}

func TestComposeHashBindsExpansion(t *testing.T) {
	p1, _, err := Compose([]byte(parentSrc), stdResolve)
	if err != nil {
		t.Fatal(err)
	}
	p2, _, err := Compose([]byte(parentSrc), stdResolve) // deterministic
	if err != nil {
		t.Fatal(err)
	}
	if p1.SemanticHash != p2.SemanticHash {
		t.Errorf("compose not deterministic: %s vs %s", p1.SemanticHash, p2.SemanticHash)
	}
	// editing the child changes the PARENT hash (the hash binds the full expansion).
	childB := strings.Replace(childSrc, `["delete_all", "shutdown"]`, `["delete_all"]`, 1)
	pB, _, err := Compose([]byte(parentSrc), mapResolver(map[string]string{"escalate_policy": childB}))
	if err != nil {
		t.Fatal(err)
	}
	if pB.SemanticHash == p1.SemanticHash {
		t.Errorf("editing the child did not change the parent hash")
	}
	// a no-composition recipe hashes identically whether via Parse or Compose (regression).
	plain, err := Parse([]byte(childSrc))
	if err != nil {
		t.Fatal(err)
	}
	cc, _, err := Compose([]byte(childSrc), stdResolve)
	if err != nil {
		t.Fatal(err)
	}
	if plain.SemanticHash != cc.SemanticHash {
		t.Errorf("no-composition hash drift: Parse=%s Compose=%s", plain.SemanticHash, cc.SemanticHash)
	}
}

func TestComposeFailClosed(t *testing.T) {
	cases := map[string]struct {
		src     string
		resolve Resolver
	}{
		"missing child": {parentSrc, mapResolver(map[string]string{})},
		"self reference": {strings.Replace(parentSrc,
			"goto_recipe: escalate_policy", "goto_recipe: router", 1), stdResolve},
		"nested composition": {parentSrc, mapResolver(map[string]string{
			// the child itself composes -> depth-1 v1 refuses it.
			"escalate_policy": strings.Replace(childSrc,
				"    kind: sink\n    in: target\n    field: mcp.escalate.action\n    sensitivity: authoritative\n    rule: esc.allowed\n    actor: \"policy:escalation\"",
				"    kind: branch\n    in: target\n    cases:\n      - rule: esc.allowed\n        goto_recipe: escalate_policy\n    default: done", 1)})},
		"unparseable child": {parentSrc, mapResolver(map[string]string{"escalate_policy": "%%% not yaml recipe"})},
		"parent not sealed": {strings.Replace(parentSrc,
			"  - id: noop\n    kind: exit\n", "", 1), stdResolve},
		"child not sealed": {parentSrc, mapResolver(map[string]string{
			"escalate_policy": strings.Replace(childSrc, "  - id: done\n    kind: exit\n", "", 1)})},
	}
	for name, c := range cases {
		p, _, err := Compose([]byte(c.src), c.resolve)
		if err == nil {
			t.Errorf("%s: want error, got none", name)
		}
		if p.SemanticHash != "" {
			t.Errorf("%s: leaked a Parsed on failure", name)
		}
	}
}

func TestComposeGrammarAndRegression(t *testing.T) {
	// goto_recipe on a NON-branch step is not a legal key.
	badSink := strings.Replace(parentSrc,
		"    field: mcp.exec.normal\n",
		"    field: mcp.exec.normal\n    goto_recipe: escalate_policy\n", 1)
	if _, err := Parse([]byte(badSink)); err == nil {
		t.Errorf("goto_recipe on a sink must be rejected")
	}
	// a case with BOTH goto and goto_recipe.
	bothCase := strings.Replace(parentSrc,
		"      - rule: route.esc\n        goto_recipe: escalate_policy",
		"      - rule: route.esc\n        goto: noop\n        goto_recipe: escalate_policy", 1)
	if _, err := Parse([]byte(bothCase)); err == nil {
		t.Errorf("case with both goto and goto_recipe must be rejected")
	}
	// a branch with BOTH default and default_recipe.
	bothDef := strings.Replace(parentSrc,
		"    default: noop",
		"    default: noop\n    default_recipe: escalate_policy", 1)
	if _, err := Parse([]byte(bothDef)); err == nil {
		t.Errorf("branch with both default and default_recipe must be rejected")
	}
	// Parse (no resolver) of a COMPOSED recipe errors clearly.
	if _, err := Parse([]byte(parentSrc)); err == nil || !strings.Contains(err.Error(), "escalate_policy") {
		t.Errorf("Parse of a composed recipe must reject with the sub-recipe name, got %v", err)
	}
	// a plain recipe parses identically through Compose(reject) and Parse (regression).
	if _, _, err := Compose([]byte(childSrc), rejectResolver); err != nil {
		t.Errorf("plain recipe must compose with no resolver: %v", err)
	}
}

func FuzzCompose(f *testing.F) {
	f.Add(parentSrc, childSrc)
	f.Add(childSrc, parentSrc)
	f.Add("recipe: r\nversion: 1\nsteps:\n  - id: a\n    kind: exit\n", childSrc)
	f.Fuzz(func(t *testing.T, parent, child string) {
		resolve := mapResolver(map[string]string{"escalate_policy": child})
		p, _, err := Compose([]byte(parent), resolve)
		if err != nil {
			if p.SemanticHash != "" {
				t.Fatalf("error AND a non-zero Parsed leaked")
			}
			return
		}
		// determinism: re-Compose yields the same semantic hash.
		p2, _, err2 := Compose([]byte(parent), resolve)
		if err2 != nil || p2.SemanticHash != p.SemanticHash {
			t.Fatalf("non-deterministic compose: %v / %s vs %s", err2, p.SemanticHash, p2.SemanticHash)
		}
		// structural sanity: unique ids, strictly-forward edges.
		seen := map[string]int{}
		for i, st := range p.Recipe.Steps {
			if _, dup := seen[st.Id]; dup {
				t.Fatalf("duplicate step id %q in composed graph", st.Id)
			}
			seen[st.Id] = i
		}
		for i, st := range p.Recipe.Steps {
			targets := []string{st.Goto, st.Default}
			for _, c := range st.Cases {
				targets = append(targets, c.Goto)
			}
			for _, tg := range targets {
				if tg == "" {
					continue
				}
				j, ok := seen[tg]
				if !ok || j <= i {
					t.Fatalf("bad edge %q -> %q (j=%d i=%d)", st.Id, tg, j, i)
				}
			}
		}
	})
}
