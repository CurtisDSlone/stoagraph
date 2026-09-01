// Package recipe is the recipe boundary: the only door through which authored
// YAML becomes a stag.Recipe. Parse -> validate -> lint -> canonicalize ->
// compile, fail closed; a rejected file is never hashed or compiled.
package recipe

// file-kw: recipe parse lint canonicalize compile boundary yaml fail-closed two hashes guarded segment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	yaml "go.yaml.in/yaml/v3"
)

// kw: recipe header name version
type Header struct {
	Name    string
	Version int64
}

// kw: parsed recipe compiled registry two hashes
type Parsed struct {
	Header       Header
	Recipe       stag.Recipe
	Rules        map[string]stag.ReleaseRule
	ArtifactHash string
	SemanticHash string
}

// kw: caps size depth nodes passthrough
const (
	maxBytes       = 65536
	maxDepth       = 32
	maxNodes       = 10000
	maxPassThrough = 64
)

// authoritativeLooking names arguments that usually PARAMETERIZE an action's effect. Declaring one
// as passthrough is legal — the operator may have a reason — but it is the kind of decision that
// should be seen, so it warns. kw: passthrough lint authoritative-looking arg names
var authoritativeLooking = map[string]bool{
	"amount": true, "to": true, "recipient": true, "path": true, "cmd": true, "command": true,
	"token": true, "key": true, "secret": true, "url": true, "host": true, "target": true,
	"namespace": true, "replicas": true, "account": true, "account_number": true, "user": true,
}

// kw: parse strict sign-time warnings are errors
func Parse(src []byte) (Parsed, error) {
	p, warns, err := parse(src)
	if err != nil {
		return Parsed{}, err
	}
	if len(warns) > 0 {
		return Parsed{}, fmt.Errorf("sign-time strict: %s", strings.Join(warns, "; "))
	}
	return p, nil
}

// kw: parse draft warnings returned
func ParseDraft(src []byte) (Parsed, []string, error) {
	p, warns, err := parse(src)
	if err != nil {
		return Parsed{}, nil, err
	}
	return p, warns, nil
}

// kw: teaching rejections ansible reflexes by name
var teaching = map[string]string{
	"when":       `key "when" is not StAG: guarded transitions are the branch kind`,
	"loop":       `key "loop" is not StAG: iteration is the foreach kind (in:/as:)`,
	"with_items": `key "with_items" is not StAG: iteration is the foreach kind (in:/as:)`,
	"register":   `key "register" is not StAG: bind results with a propose out: slot`,
	"vars":       `key "vars" is not StAG: use declared ingredients and release rules`,
	"notify":     `key "notify" is not StAG: there are no handlers`,
	"become":     `key "become" is not StAG: there is no privilege escalation`,
	"on":         `key "on" is a YAML 1.1 boolean; use in:`,
}

// kw: line-anchored error
func errf(n *yaml.Node, format string, args ...any) error {
	if n != nil && n.Line > 0 {
		return fmt.Errorf("line %d: %s", n.Line, fmt.Sprintf(format, args...))
	}
	return fmt.Errorf(format, args...)
}

// kw: name grammar ascii closed
func nameOK(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// kw: rule id grammar dotted segments
func ruleIdOK(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	segs := strings.Split(s, ".")
	if len(segs) < 1 || len(segs) > 4 {
		return false
	}
	for _, seg := range segs {
		if !nameOK(seg) {
			return false
		}
	}
	return true
}

// kw: raw step intermediate
type rawCase struct {
	rule    string
	gto     string
	gtoReci string // composition: goto_recipe target (mutually exclusive with gto)
	node    *yaml.Node
}

type rawStep struct {
	node      *yaml.Node
	id        string
	kind      stag.NodeKind
	out       string
	in        string
	as        string // foreach: per-element out-slot
	field     string
	sens      stag.SinkSensitivity
	ruleRef   string
	actor     string
	gto       string
	escalate  bool
	cases     []rawCase
	deflt     string
	defltReci string // composition: default_recipe target (mutually exclusive with deflt)
}

// kw: resolver composition sub-recipe source by name
type Resolver func(name string) ([]byte, error)

// rejectResolver refuses composition — recipe.Parse/ParseDraft use it, so a recipe
// that references a sub-recipe errors clearly unless a store-backed resolver is supplied.
func rejectResolver(name string) ([]byte, error) {
	return nil, fmt.Errorf("sub-recipe %q referenced but composition has no recipe store/resolver", name)
}

// front is everything a recipe yields BEFORE the cross-step lint: the schema-validated
// raw pieces. Composition splices children into a front, then lint+hash+compile run once
// over the composed whole (finish). kw: front-parse compose splice pre-lint
type front struct {
	name        string
	version     int64
	ingOrder    []string
	ingredients map[string]stag.Slot
	ruleOrder   []string
	registry    map[string]stag.ReleaseRule
	steps       []rawStep
	passthrough []string // tool args knowingly forwarded ungated (the coverage contract)
}

// Parse is Compose with no resolver (composition disabled). kw: parse strict
func parse(src []byte) (Parsed, []string, error) { return Compose(src, rejectResolver) }

// Compose front-parses the parent, inlines every goto_recipe/default_recipe sub-recipe
// (namespaced, spliced), then lints+hashes+compiles the composed whole. The parent's
// SemanticHash binds the FULL expansion. Draft semantics (returns warnings). ZERO kernel
// change: the kernel Evals one flattened graph; the inliner is re-linted, not trusted.
func Compose(src []byte, resolve Resolver) (Parsed, []string, error) {
	fr, warns, err := frontParse(src)
	if err != nil {
		return Parsed{}, nil, err
	}
	if fr.hasComposition() && !fr.sealed() {
		return Parsed{}, nil, fmt.Errorf("a recipe that composes a sub-recipe must end with an exit step (kind: exit as the last step) so an inlined sub-recipe cannot be reached by fall-through")
	}
	if err := fr.inline(resolve); err != nil {
		return Parsed{}, nil, err
	}
	return finish(fr, warns, src)
}

// sealed reports whether the recipe ends with an explicit exit terminal. With forward-only
// edges this guarantees no path falls off the end — the precondition for safely appending
// (inlining) another recipe after it. kw: composition seal terminal exit
func (fr *front) sealed() bool {
	return len(fr.steps) > 0 && fr.steps[len(fr.steps)-1].kind == stag.NodeExit
}

// kw: composition bound sub-recipe references per recipe
const maxComposeSites = 64

// hasComposition reports whether any branch step references a sub-recipe.
func (fr *front) hasComposition() bool {
	for _, st := range fr.steps {
		if st.defltReci != "" {
			return true
		}
		for _, c := range st.cases {
			if c.gtoReci != "" {
				return true
			}
		}
	}
	return false
}

// inline expands every goto_recipe/default_recipe reference by splicing the named
// sub-recipe (namespaced) into fr. Sites are processed in document order (deterministic),
// collected BEFORE splicing so appending children never invalidates a step index. v1: the
// child is a TAIL (runs to its own terminals), depth-1 (a child may not itself compose),
// no self-reference; finish re-lints the composed whole (the inliner is not trusted).
func (fr *front) inline(resolve Resolver) error {
	type site struct {
		step, kase int // kase = -1 marks the default target
		child      string
		node       *yaml.Node
	}
	var sites []site
	for si, st := range fr.steps {
		for ci, c := range st.cases {
			if c.gtoReci != "" {
				sites = append(sites, site{si, ci, c.gtoReci, st.node})
			}
		}
		if st.defltReci != "" {
			sites = append(sites, site{si, -1, st.defltReci, st.node})
		}
	}
	if len(sites) > maxComposeSites {
		return fmt.Errorf("too many sub-recipe references: %d (max %d)", len(sites), maxComposeSites)
	}
	for n, s := range sites {
		entry, err := fr.splice(s.child, n, resolve, s.node)
		if err != nil {
			return err
		}
		if s.kase >= 0 {
			fr.steps[s.step].cases[s.kase].gto, fr.steps[s.step].cases[s.kase].gtoReci = entry, ""
		} else {
			fr.steps[s.step].deflt, fr.steps[s.step].defltReci = entry, ""
		}
	}
	return nil
}

// splice resolves, front-parses, and namespaces a child, then appends its steps/slots/
// rules to fr. Returns the child's namespaced entry step id. Fails closed on a missing
// child, self-reference, or a child that itself composes (nesting is out of scope in v1).
func (fr *front) splice(name string, site int, resolve Resolver, at *yaml.Node) (string, error) {
	if name == fr.name {
		return "", errf(at, "sub-recipe %q references itself (composition is acyclic)", name)
	}
	b, err := resolve(name)
	if err != nil {
		return "", errf(at, "sub-recipe %q: %v", name, err)
	}
	cf, _, err := frontParse(b)
	if err != nil {
		return "", errf(at, "sub-recipe %q: %v", name, err)
	}
	if cf.hasComposition() {
		return "", errf(at, "sub-recipe %q itself composes: nested composition is not supported in v1", name)
	}
	if !cf.sealed() {
		return "", errf(at, "sub-recipe %q must end with an exit step (kind: exit) to be inlined as a tail", name)
	}
	cf.namespace(fmt.Sprintf("s%d_", site))
	fr.ingOrder = append(fr.ingOrder, cf.ingOrder...)
	for k, v := range cf.ingredients {
		fr.ingredients[k] = v
	}
	// PassThrough is NOT namespaced: it names real tool arguments, not slots. A child's coverage
	// contract is unioned into the parent's — the composed whole is what the gate enforces, and the
	// parent's SemanticHash binds it.
	fr.passthrough = unionSorted(fr.passthrough, cf.passthrough)
	fr.ruleOrder = append(fr.ruleOrder, cf.ruleOrder...)
	for k, v := range cf.registry {
		fr.registry[k] = v
	}
	entry := cf.steps[0].id // the child's (namespaced) first step is its entry
	fr.steps = append(fr.steps, cf.steps...)
	return entry, nil
}

// namespace prefixes every id, slot, and rule id in the child so it cannot collide with
// the parent or another inlined child. Every child edge/ref points within the child, so a
// uniform prefix preserves them. field and actor are real target identifiers (the
// actuator's sink field + the authorizing actor), NOT slots — they are left untouched.
func (fr *front) namespace(p string) {
	ni := make(map[string]stag.Slot, len(fr.ingredients))
	for i, n := range fr.ingOrder {
		fr.ingOrder[i] = p + n
		ni[p+n] = fr.ingredients[n]
	}
	fr.ingredients = ni
	nr := make(map[string]stag.ReleaseRule, len(fr.registry))
	for i, id := range fr.ruleOrder {
		fr.ruleOrder[i] = p + id
		nr[p+id] = fr.registry[id]
	}
	fr.registry = nr
	pre := func(s string) string {
		if s == "" {
			return ""
		}
		return p + s
	}
	for i := range fr.steps {
		st := &fr.steps[i]
		st.id = p + st.id
		st.in, st.out, st.as = pre(st.in), pre(st.out), pre(st.as)
		st.gto, st.deflt = pre(st.gto), pre(st.deflt)
		st.ruleRef = pre(st.ruleRef)
		for ci := range st.cases {
			st.cases[ci].gto = pre(st.cases[ci].gto)
			st.cases[ci].rule = pre(st.cases[ci].rule)
		}
	}
}

// kw: front-parse prelims decode hygiene schema (no cross-step lint — finish does that)
func frontParse(src []byte) (fr front, warns []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			fr, warns, err = front{}, nil, fmt.Errorf("yaml panic recovered: %v", r)
		}
	}()

	// prelims (rules 1-3): before yaml sees a byte
	if len(src) > maxBytes {
		return front{}, nil, fmt.Errorf("input too large: %d bytes (max %d)", len(src), maxBytes)
	}
	if bytes.HasPrefix(src, []byte{0xEF, 0xBB, 0xBF}) || bytes.HasPrefix(src, []byte{0xFE, 0xFF}) || bytes.HasPrefix(src, []byte{0xFF, 0xFE}) {
		return front{}, nil, errors.New("byte-order mark (BOM) not allowed: recipes are UTF-8, no BOM")
	}
	if bytes.IndexByte(src, 0) >= 0 {
		return front{}, nil, errors.New("NUL byte in input")
	}
	if !utf8.Valid(src) {
		return front{}, nil, errors.New("invalid UTF-8")
	}

	// document (rules 4-5): exactly one, root a mapping
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc yaml.Node
	if derr := dec.Decode(&doc); derr != nil {
		if derr == io.EOF {
			return front{}, nil, errors.New("empty document")
		}
		return front{}, nil, fmt.Errorf("yaml: %v", derr)
	}
	var extra yaml.Node
	if derr := dec.Decode(&extra); derr != io.EOF {
		return front{}, nil, errors.New("recipe must be exactly one document")
	}
	if len(doc.Content) == 0 {
		return front{}, nil, errors.New("empty document")
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return front{}, nil, errors.New("empty document")
	}
	if root.Kind != yaml.MappingNode {
		return front{}, nil, errf(root, "recipe root must be a mapping")
	}

	if herr := hygiene(root); herr != nil {
		return front{}, nil, herr
	}

	// schema: top level
	var name string
	var version int64
	var haveName, haveVersion, haveSteps bool
	ingOrder := []string{}
	ingredients := map[string]stag.Slot{}
	ruleOrder := []string{}
	registry := map[string]stag.ReleaseRule{}
	var steps []rawStep
	var passthrough []string

	for i := 0; i < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "passthrough":
			// The coverage contract: tool arguments this policy knowingly forwards UNGATED.
			// Everything else the tool takes must be gated, or the call is denied (unaccounted).
			if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
				return front{}, nil, errf(v, "passthrough must be a non-empty sequence (omit the key to gate every argument)")
			}
			if len(v.Content) > maxPassThrough {
				return front{}, nil, errf(v, "too many passthrough args: %d (max %d)", len(v.Content), maxPassThrough)
			}
			seen := map[string]bool{}
			for _, an := range v.Content {
				s, serr := quotedStr(an, "passthrough arg")
				if serr != nil {
					return front{}, nil, serr
				}
				if !nameOK(s) {
					return front{}, nil, errf(an, "invalid passthrough arg %q (grammar: lowercase ascii, digits, _, max 64)", s)
				}
				if seen[s] {
					return front{}, nil, errf(an, "duplicate passthrough arg %q", s)
				}
				seen[s] = true
				passthrough = append(passthrough, s)
			}
			sort.Strings(passthrough) // canonical order: the hash must not depend on authoring order
		case "recipe":
			s, serr := strVal(v, "recipe name")
			if serr != nil {
				return front{}, nil, serr
			}
			if !nameOK(s) {
				return front{}, nil, errf(v, "invalid name %q (grammar: lowercase ascii, digits, _, max 64)", s)
			}
			name, haveName = s, true
		case "version":
			n, nerr := intVal(v, "version")
			if nerr != nil {
				return front{}, nil, nerr
			}
			if n != 1 {
				return front{}, nil, errf(v, "version must be 1 (got %d)", n)
			}
			version, haveVersion = n, true
		case "ingredients":
			if v.Kind != yaml.MappingNode {
				return front{}, nil, errf(v, "ingredients must be a mapping")
			}
			for j := 0; j < len(v.Content); j += 2 {
				ik, iv := v.Content[j], v.Content[j+1]
				if !nameOK(ik.Value) {
					return front{}, nil, errf(ik, "invalid name %q for ingredient", ik.Value)
				}
				slot, serr := parseIngredient(iv)
				if serr != nil {
					return front{}, nil, serr
				}
				ingOrder = append(ingOrder, ik.Value)
				ingredients[ik.Value] = slot
			}
		case "rules":
			if v.Kind != yaml.MappingNode {
				return front{}, nil, errf(v, "rules must be a mapping")
			}
			for j := 0; j < len(v.Content); j += 2 {
				rk, rv := v.Content[j], v.Content[j+1]
				if !ruleIdOK(rk.Value) {
					return front{}, nil, errf(rk, "invalid rule id %q (dot-separated lowercase segments)", rk.Value)
				}
				rule, w, rerr := parseRule(rk.Value, rv)
				if rerr != nil {
					return front{}, nil, rerr
				}
				warns = append(warns, w...)
				ruleOrder = append(ruleOrder, rk.Value)
				registry[rk.Value] = rule
			}
		case "steps":
			if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
				return front{}, nil, errf(v, "steps must be a non-empty sequence")
			}
			for j, sn := range v.Content {
				st, serr := parseStep(j, sn)
				if serr != nil {
					return front{}, nil, serr
				}
				steps = append(steps, st)
			}
			haveSteps = true
		default:
			return front{}, nil, errf(k, "unknown key %q at top level", k.Value)
		}
	}
	if !haveName || !haveVersion || !haveSteps {
		return front{}, nil, fmt.Errorf("missing required key: recipe, version, and steps are required")
	}
	return front{
		name: name, version: version,
		ingOrder: ingOrder, ingredients: ingredients,
		ruleOrder: ruleOrder, registry: registry, steps: steps,
		passthrough: passthrough,
	}, warns, nil
}

// finish runs the cross-step lint, canonical hash, and compile over a (possibly composed)
// front. src is the parent source (its bytes are the ArtifactHash; the SemanticHash is
// over the composed canonical form). kw: lint canonicalize compile the two hashes
func finish(fr front, warns []string, src []byte) (Parsed, []string, error) {
	name, version := fr.name, fr.version
	ingOrder, ingredients := fr.ingOrder, fr.ingredients
	ruleOrder, registry := fr.ruleOrder, fr.registry
	steps := fr.steps

	lintWarns, lerr := lint(ingredients, registry, steps)
	if lerr != nil {
		return Parsed{}, nil, lerr
	}
	warns = append(warns, lintWarns...)
	warns = append(warns, lintPassThrough(fr.passthrough, steps)...)

	// canonical form + the two hashes (decision 2): built from validated raw
	// text, never from yaml-decoded values; rejected files never reach here.
	form := map[string]any{"recipe": name, "version": version}
	// The coverage contract is part of the policy IDENTITY: adding an argument to passthrough
	// widens what crosses ungated, so it must move the SemanticHash the audit records.
	if len(fr.passthrough) > 0 {
		pt := make([]any, len(fr.passthrough))
		for i, a := range fr.passthrough {
			pt[i] = a
		}
		form["passthrough"] = pt
	}
	if len(ingOrder) > 0 {
		im := map[string]any{}
		for _, n := range ingOrder {
			im[n] = map[string]any{"origin": ingredients[n].Origin, "trust": ingredients[n].Class.String()}
		}
		form["ingredients"] = im
	}
	if len(ruleOrder) > 0 {
		rm := map[string]any{}
		for _, id := range ruleOrder {
			r := registry[id]
			e := map[string]any{"kind": r.Kind.String()}
			switch r.Kind {
			case stag.RuleSetMembership:
				members := make([]any, len(r.Set))
				for i, m := range r.Set {
					members[i] = m
				}
				e["set"] = members
			case stag.RuleSignedEquality:
				e["signed"] = r.Signed
			case stag.RuleNumericRange:
				e["min"], e["max"] = r.Min, r.Max
			}
			rm[id] = e
		}
		form["rules"] = rm
	}
	stepForms := make([]any, len(steps))
	for i, st := range steps {
		e := map[string]any{"id": st.id, "kind": st.kind.String()}
		switch st.kind {
		case stag.NodePropose:
			e["out"] = st.out
			if st.gto != "" {
				e["goto"] = st.gto
			}
		case stag.NodeSink:
			e["in"], e["field"], e["sensitivity"] = st.in, st.field, st.sens.String()
			if st.ruleRef != "" {
				e["rule"], e["actor"] = st.ruleRef, st.actor
			}
			if st.gto != "" {
				e["goto"] = st.gto
			}
		case stag.NodeGate:
			e["in"], e["rule"] = st.in, st.ruleRef
			if st.escalate {
				e["on_fail"] = "escalate"
			} else {
				e["on_fail"] = "deny"
			}
		case stag.NodeBranch:
			e["in"], e["default"] = st.in, st.deflt
			cs := make([]any, len(st.cases))
			for j, c := range st.cases {
				cs[j] = map[string]any{"rule": c.rule, "goto": c.gto}
			}
			e["cases"] = cs
		case stag.NodeForeach:
			e["in"], e["as"] = st.in, st.as
			if st.gto != "" {
				e["goto"] = st.gto
			}
		}
		stepForms[i] = e
	}
	form["steps"] = stepForms

	semantic, herr := stag.CanonicalHash(form)
	if herr != nil {
		return Parsed{}, nil, fmt.Errorf("canonicalize: %v", herr)
	}
	sum := sha256.Sum256(src)

	// compile
	compiled := stag.Recipe{Steps: make([]stag.Step, len(steps))}
	if len(ingredients) > 0 {
		compiled.Ingredients = ingredients
	}
	if len(fr.passthrough) > 0 {
		compiled.PassThrough = fr.passthrough
	}
	for i, st := range steps {
		out := stag.Step{
			Id: st.id, Kind: st.kind, Out: st.out, In: st.in, As: st.as, Sensitivity: st.sens,
			Field: st.field, Actor: st.actor, Goto: st.gto, Escalate: st.escalate, Default: st.deflt,
		}
		if st.ruleRef != "" {
			r := registry[st.ruleRef] // one registry entry binds label and predicate
			out.Rule, out.RuleID = &r, st.ruleRef
		}
		for _, c := range st.cases {
			cr := registry[c.rule]
			out.Cases = append(out.Cases, stag.Case{Rule: &cr, Goto: c.gto})
		}
		compiled.Steps[i] = out
	}

	return Parsed{
		Header:       Header{Name: name, Version: version},
		Recipe:       compiled,
		Rules:        registry,
		ArtifactHash: hex.EncodeToString(sum[:]),
		SemanticHash: semantic,
	}, warns, nil
}

// unionSorted merges two arg-name lists into one sorted, deduplicated list (composition unions the
// children's coverage contracts into the parent's). kw: passthrough union compose canonical
func unionSorted(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// lintPassThrough reports a coverage contract that is WRONG (not merely bold): an argument that is
// both gated and declared passthrough. The gate wins, so the declaration is dead policy — the same
// class as a rule on a benign sink. Sign-time strict turns this into an error, which is right: it
// means the author believes something about their own policy that is not true.
//
// Whether a passthrough is *unwise* is a judgment, not an error — see Cautions.
// kw: passthrough lint contradiction dead-declaration
func lintPassThrough(passthrough []string, steps []rawStep) []string {
	if len(passthrough) == 0 {
		return nil
	}
	gated := map[string]bool{}
	for _, st := range steps {
		if st.kind == stag.NodePropose {
			gated[st.out] = true
		}
	}
	var warns []string
	for _, a := range passthrough {
		if gated[a] {
			warns = append(warns, fmt.Sprintf("argument %q is both gated and declared passthrough (the gate wins; the declaration is dead)", a))
		}
	}
	sort.Strings(warns)
	return warns
}

// Cautions reports passthrough declarations a human should look at twice: an argument whose NAME
// suggests it parameterizes the action's effect, forwarded ungated.
//
// This is deliberately NOT a lint warning. Sign-time strict makes warnings errors, and a name-based
// heuristic must never be able to REFUSE a policy — an operator may have a real reason to wave
// `path` through, and a blocklist of names is not the kind of thing that should be able to stop
// them. It is an advisory the console and CLI surface; it never blocks a save.
// kw: passthrough caution advisory non-blocking authoritative-looking
func Cautions(p Parsed) []string {
	var out []string
	for _, a := range p.Recipe.PassThrough {
		if authoritativeLooking[a] {
			out = append(out, fmt.Sprintf("passthrough %q looks authoritative: this policy forwards it UNGATED, so nothing bounds its value", a))
		}
	}
	sort.Strings(out)
	return out
}

// kw: hygiene walk iterative caps anchors aliases merge duplicate keys teaching
func hygiene(root *yaml.Node) error {
	type frame struct {
		n     *yaml.Node
		depth int
	}
	stack := []frame{{root, 1}}
	nodes := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > maxNodes {
			return errors.New("too many nodes")
		}
		if f.depth > maxDepth {
			return errf(f.n, "nesting depth exceeds %d", maxDepth)
		}
		n := f.n
		if n.Kind == yaml.AliasNode {
			return errf(n, "alias not allowed (the rules registry is the only reuse mechanism)")
		}
		if n.Anchor != "" {
			return errf(n, "anchor not allowed")
		}
		switch n.Kind {
		case yaml.MappingNode:
			if n.Tag != "" && n.Tag != "!!map" {
				return errf(n, "custom tag %q not allowed", n.Tag)
			}
			seen := map[string]bool{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind == yaml.AliasNode {
					return errf(k, "alias not allowed")
				}
				if k.Anchor != "" {
					return errf(k, "anchor not allowed")
				}
				if msg, hit := teaching[k.Value]; hit && k.Kind == yaml.ScalarNode {
					return errf(k, "%s", msg)
				}
				if k.Value == "<<" || k.Tag == "!!merge" {
					return errf(k, "merge key not allowed")
				}
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
					return errf(k, "mapping key must be a plain string")
				}
				if seen[k.Value] {
					return errf(k, "duplicate key %q", k.Value)
				}
				seen[k.Value] = true
				stack = append(stack, frame{n.Content[i+1], f.depth + 1})
			}
		case yaml.SequenceNode:
			if n.Tag != "" && n.Tag != "!!seq" {
				return errf(n, "custom tag %q not allowed", n.Tag)
			}
			for _, c := range n.Content {
				stack = append(stack, frame{c, f.depth + 1})
			}
		}
	}
	return nil
}

// kw: yaml 1.1 ambiguous plain scalars cross-tool differential
var yaml11Ambiguous = map[string]bool{
	"y": true, "Y": true, "yes": true, "Yes": true, "YES": true,
	"n": true, "N": true, "no": true, "No": true, "NO": true,
	"on": true, "On": true, "ON": true, "off": true, "Off": true, "OFF": true,
	"true": true, "True": true, "TRUE": true, "false": true, "False": true, "FALSE": true,
	"null": true, "Null": true, "NULL": true, "~": true,
}

// kw: scalar string raw text tag allowlist templating
func strVal(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", errf(n, "%s must be a string; ambiguous scalars must be quoted (got %s)", what, n.Tag)
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 && yaml11Ambiguous[n.Value] {
		return "", errf(n, "%s %q is an ambiguous YAML 1.1 scalar and must be quoted (other tools would read it as a boolean)", what, n.Value)
	}
	if strings.Contains(n.Value, "{{") {
		return "", errf(n, "%s contains {{: templating is not StAG, values are data", what)
	}
	for _, r := range n.Value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", errf(n, "%s contains a control character (U+%04X); values ride verbatim into signed fields", what, r)
		}
	}
	return n.Value, nil
}

// kw: scalar quoted required byte-exact
func quotedStr(n *yaml.Node, what string) (string, error) {
	s, err := strVal(n, what)
	if err != nil {
		return "", err
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 {
		return "", errf(n, "%s must be quoted", what)
	}
	return s, nil
}

// kw: scalar canonical integer kernel predicate
func intVal(n *yaml.Node, what string) (int64, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		return 0, errf(n, "%s must be a canonical integer (got %s %q)", what, n.Tag, n.Value)
	}
	v, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil || n.Value != strconv.FormatInt(v, 10) {
		return 0, errf(n, "%s must be a canonical integer (got %q)", what, n.Value)
	}
	return v, nil
}

// kw: ingredient origin trust closed keys value unauthorable
func parseIngredient(n *yaml.Node) (stag.Slot, error) {
	if n.Kind != yaml.MappingNode {
		return stag.Slot{}, errf(n, "ingredient must be a mapping")
	}
	var origin string
	var class stag.TrustClass
	var haveOrigin, haveTrust bool
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "origin":
			s, err := strVal(v, "origin")
			if err != nil {
				return stag.Slot{}, err
			}
			origin, haveOrigin = s, true
		case "trust":
			s, err := strVal(v, "trust")
			if err != nil {
				return stag.Slot{}, err
			}
			c, err := stag.ParseTrustClass(s)
			if err != nil {
				return stag.Slot{}, errf(v, "%v: %q", err, s)
			}
			class, haveTrust = c, true
		default:
			return stag.Slot{}, errf(k, "unknown key %q for ingredient (a value: key is never authorable)", k.Value)
		}
	}
	if !haveOrigin || !haveTrust {
		return stag.Slot{}, errf(n, "ingredient requires origin and trust")
	}
	return stag.Slot{Class: class, Origin: origin}, nil
}

// kw: rule registry per-kind required forbidden sorted set
func parseRule(id string, n *yaml.Node) (stag.ReleaseRule, []string, error) {
	if n.Kind != yaml.MappingNode {
		return stag.ReleaseRule{}, nil, errf(n, "rule %s must be a mapping", id)
	}
	byKey := map[string]*yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		byKey[n.Content[i].Value] = n.Content[i+1]
	}
	kn, ok := byKey["kind"]
	if !ok {
		return stag.ReleaseRule{}, nil, errf(n, "rule %s is missing kind", id)
	}
	ks, err := strVal(kn, "rule kind")
	if err != nil {
		return stag.ReleaseRule{}, nil, err
	}
	kind, err := stag.ParseRuleKind(ks)
	if err != nil {
		return stag.ReleaseRule{}, nil, errf(kn, "%v", err)
	}
	legal := map[stag.RuleKind]map[string]bool{
		stag.RuleSetMembership:  {"kind": true, "set": true},
		stag.RuleSignedEquality: {"kind": true, "signed": true},
		stag.RuleNumericRange:   {"kind": true, "min": true, "max": true},
	}[kind]
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i]; !legal[k.Value] {
			return stag.ReleaseRule{}, nil, errf(k, "key %q not legal for %s", k.Value, kind)
		}
	}
	var warns []string
	rule := stag.ReleaseRule{Kind: kind}
	switch kind {
	case stag.RuleSetMembership:
		sn, ok := byKey["set"]
		if !ok {
			return stag.ReleaseRule{}, nil, errf(n, "set_membership requires set")
		}
		if sn.Kind != yaml.SequenceNode || len(sn.Content) == 0 {
			return stag.ReleaseRule{}, nil, errf(sn, "empty set releases nothing")
		}
		seen := map[string]bool{}
		for _, m := range sn.Content {
			s, err := quotedStr(m, "set member")
			if err != nil {
				return stag.ReleaseRule{}, nil, err
			}
			if seen[s] {
				return stag.ReleaseRule{}, nil, errf(m, "duplicate set member %q", s)
			}
			seen[s] = true
			if s == "" {
				warns = append(warns, fmt.Sprintf("empty string set member in rule %s", id))
			}
			rule.Set = append(rule.Set, s)
		}
		sort.Strings(rule.Set) // canonical order
	case stag.RuleSignedEquality:
		sn, ok := byKey["signed"]
		if !ok {
			return stag.ReleaseRule{}, nil, errf(n, "signed_equality requires signed")
		}
		s, err := quotedStr(sn, "signed value")
		if err != nil {
			return stag.ReleaseRule{}, nil, err
		}
		if s == "" {
			return stag.ReleaseRule{}, nil, errf(sn, "empty signed value releases nothing")
		}
		rule.Signed = s
	case stag.RuleNumericRange:
		mn, okMin := byKey["min"]
		mx, okMax := byKey["max"]
		if !okMin || !okMax {
			return stag.ReleaseRule{}, nil, errf(n, "numeric_range requires min and max")
		}
		lo, err := intVal(mn, "min")
		if err != nil {
			return stag.ReleaseRule{}, nil, err
		}
		hi, err := intVal(mx, "max")
		if err != nil {
			return stag.ReleaseRule{}, nil, err
		}
		if lo > hi {
			return stag.ReleaseRule{}, nil, errf(mn, "min %d greater than max %d", lo, hi)
		}
		rule.Min, rule.Max = lo, hi
	}
	return rule, warns, nil
}

// kw: step per-kind key tables vocabulary foreach exit distinct
func parseStep(idx int, n *yaml.Node) (rawStep, error) {
	if n.Kind != yaml.MappingNode {
		return rawStep{}, errf(n, "step %d must be a mapping", idx)
	}
	byKey := map[string]*yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		byKey[n.Content[i].Value] = n.Content[i+1]
	}
	st := rawStep{node: n}
	idn, ok := byKey["id"]
	if !ok {
		return rawStep{}, errf(n, "step %d is missing id", idx)
	}
	id, err := strVal(idn, "id")
	if err != nil {
		return rawStep{}, err
	}
	if !nameOK(id) {
		return rawStep{}, errf(idn, "invalid name %q for step id", id)
	}
	st.id = id
	kn, ok := byKey["kind"]
	if !ok {
		return rawStep{}, errf(n, "step %q is missing kind", id)
	}
	ks, err := strVal(kn, "kind")
	if err != nil {
		return rawStep{}, err
	}
	kind, err := stag.ParseNodeKind(ks)
	if err != nil {
		return rawStep{}, errf(kn, "unknown kind %q", ks)
	}
	st.kind = kind

	legal := map[stag.NodeKind]map[string]bool{
		stag.NodePropose: {"id": true, "kind": true, "out": true, "goto": true},
		stag.NodeSink:    {"id": true, "kind": true, "in": true, "field": true, "sensitivity": true, "rule": true, "actor": true, "goto": true},
		stag.NodeGate:    {"id": true, "kind": true, "in": true, "rule": true, "on_fail": true},
		stag.NodeBranch:  {"id": true, "kind": true, "in": true, "cases": true, "default": true, "default_recipe": true},
		stag.NodeForeach: {"id": true, "kind": true, "in": true, "as": true, "goto": true},
		stag.NodeExit:    {"id": true, "kind": true},
	}[kind]
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i]; !legal[k.Value] {
			return rawStep{}, errf(k, "key %q not legal for %s", k.Value, kind)
		}
	}

	need := func(key, what string) (string, error) {
		vn, ok := byKey[key]
		if !ok {
			return "", errf(n, "%s %q requires %s", kind, id, key)
		}
		return strVal(vn, what)
	}
	switch kind {
	case stag.NodePropose:
		out, err := need("out", "out")
		if err != nil {
			return rawStep{}, err
		}
		if !nameOK(out) {
			return rawStep{}, errf(byKey["out"], "invalid name %q for out slot", out)
		}
		st.out = out
	case stag.NodeSink:
		if st.in, err = need("in", "in"); err != nil {
			return rawStep{}, err
		}
		if st.field, err = need("field", "field"); err != nil {
			return rawStep{}, err
		}
		sens, err := need("sensitivity", "sensitivity")
		if err != nil {
			return rawStep{}, err
		}
		if st.sens, err = stag.ParseSinkSensitivity(sens); err != nil {
			return rawStep{}, errf(byKey["sensitivity"], "%v", err)
		}
		if rn, ok := byKey["rule"]; ok {
			ref, err := strVal(rn, "rule")
			if err != nil {
				return rawStep{}, err
			}
			if st.sens == stag.SinkBenign {
				return rawStep{}, errf(rn, "rule on a benign sink is dead policy (release is never consulted)")
			}
			st.ruleRef = ref
			actor, err := need("actor", "actor")
			if err != nil {
				return rawStep{}, errf(n, "actor is required when a rule is present (sink %q)", id)
			}
			st.actor = actor
		} else if _, ok := byKey["actor"]; ok {
			return rawStep{}, errf(byKey["actor"], "actor without a rule on sink %q", id)
		}
	case stag.NodeGate:
		if st.in, err = need("in", "in"); err != nil {
			return rawStep{}, err
		}
		if st.ruleRef, err = need("rule", "rule"); err != nil {
			return rawStep{}, err
		}
		if fn, ok := byKey["on_fail"]; ok {
			s, err := strVal(fn, "on_fail")
			if err != nil {
				return rawStep{}, err
			}
			switch s {
			case "deny":
			case "escalate":
				st.escalate = true
			default:
				return rawStep{}, errf(fn, "on_fail must be deny or escalate (got %q)", s)
			}
		}
	case stag.NodeBranch:
		if st.in, err = need("in", "in"); err != nil {
			return rawStep{}, err
		}
		cn, ok := byKey["cases"]
		if !ok || cn.Kind != yaml.SequenceNode || len(cn.Content) == 0 {
			return rawStep{}, errf(n, "branch %q cases must be a non-empty sequence", id)
		}
		for _, c := range cn.Content {
			if c.Kind != yaml.MappingNode {
				return rawStep{}, errf(c, "branch case must be a mapping")
			}
			var rc rawCase
			rc.node = c
			for i := 0; i < len(c.Content); i += 2 {
				ck, cv := c.Content[i], c.Content[i+1]
				switch ck.Value {
				case "rule":
					if rc.rule, err = strVal(cv, "case rule"); err != nil {
						return rawStep{}, err
					}
				case "goto":
					if rc.gto, err = strVal(cv, "case goto"); err != nil {
						return rawStep{}, err
					}
				case "goto_recipe": // composition: inline a sub-recipe on this case
					if rc.gtoReci, err = strVal(cv, "case goto_recipe"); err != nil {
						return rawStep{}, err
					}
				default:
					return rawStep{}, errf(ck, "key %q not legal for a branch case", ck.Value)
				}
			}
			if rc.rule == "" {
				return rawStep{}, errf(c, "branch case requires rule")
			}
			if (rc.gto == "") == (rc.gtoReci == "") { // exactly one target
				return rawStep{}, errf(c, "branch case requires exactly one of goto or goto_recipe")
			}
			st.cases = append(st.cases, rc)
		}
		dn, haveD := byKey["default"]
		rn, haveDR := byKey["default_recipe"]
		if haveD == haveDR { // exactly one default target
			return rawStep{}, errf(n, "branch %q requires exactly one of default or default_recipe", id)
		}
		if haveD {
			if st.deflt, err = strVal(dn, "default"); err != nil {
				return rawStep{}, err
			}
		} else {
			if st.defltReci, err = strVal(rn, "default_recipe"); err != nil {
				return rawStep{}, err
			}
		}
	case stag.NodeForeach:
		if st.in, err = need("in", "in"); err != nil {
			return rawStep{}, err
		}
		as, err := need("as", "as")
		if err != nil {
			return rawStep{}, err
		}
		if !nameOK(as) {
			return rawStep{}, errf(byKey["as"], "invalid name %q for as slot", as)
		}
		st.as = as
	}
	if gn, ok := byKey["goto"]; ok && kind != stag.NodeBranch && kind != stag.NodeGate {
		if st.gto, err = strVal(gn, "goto"); err != nil {
			return rawStep{}, err
		}
	}
	return st, nil
}

// kw: lint declare-before-use edges reachability guaranteed-deny guarded segment dead declarations
func lint(ingredients map[string]stag.Slot, registry map[string]stag.ReleaseRule, steps []rawStep) ([]string, error) {
	n := len(steps)
	idx := map[string]int{}
	for i, st := range steps {
		if _, dup := idx[st.id]; dup {
			return nil, errf(st.node, "duplicate id %q", st.id)
		}
		idx[st.id] = i
	}

	// declare-before-use + duplicate outs + static classes
	static := map[string]stag.TrustClass{}
	for name, slot := range ingredients {
		static[name] = slot.Class
	}
	usedIngredient := map[string]bool{}
	declared := map[string]bool{}
	for name := range ingredients {
		declared[name] = true
	}
	foreachCount := 0
	for _, st := range steps {
		if st.kind == stag.NodePropose {
			if declared[st.out] {
				return nil, errf(st.node, "duplicate out slot %q", st.out)
			}
			declared[st.out] = true
			static[st.out] = stag.Untrusted
			continue
		}
		if st.kind == stag.NodeForeach {
			foreachCount++
			if foreachCount > 1 {
				return nil, errf(st.node, "at most one foreach per recipe (nesting is not supported in v1)")
			}
			if !declared[st.in] {
				return nil, errf(st.node, "undeclared slot %q (declare-before-use)", st.in)
			}
			if _, isIng := ingredients[st.in]; isIng {
				usedIngredient[st.in] = true
			}
			if declared[st.as] { // foreach defines its element slot
				return nil, errf(st.node, "duplicate as slot %q", st.as)
			}
			declared[st.as] = true
			static[st.as] = stag.Untrusted
			continue
		}
		if st.kind == stag.NodeExit {
			continue // a pure terminal: consumes no slot
		}
		if !declared[st.in] {
			return nil, errf(st.node, "undeclared slot %q (declare-before-use)", st.in)
		}
		if _, isIng := ingredients[st.in]; isIng {
			usedIngredient[st.in] = true
		}
	}

	// rule references + unique fields + guaranteed-deny
	usedRule := map[string]bool{}
	ref := func(st rawStep, id string) error {
		if _, ok := registry[id]; !ok {
			return errf(st.node, "unregistered rule %q", id)
		}
		usedRule[id] = true
		return nil
	}
	fields := map[string]bool{}
	for _, st := range steps {
		if st.ruleRef != "" {
			if err := ref(st, st.ruleRef); err != nil {
				return nil, err
			}
		}
		for _, c := range st.cases {
			if err := ref(st, c.rule); err != nil {
				return nil, err
			}
		}
		if st.kind == stag.NodeSink {
			if fields[st.field] {
				return nil, errf(st.node, "duplicate field %q (aliased fields collapse the event-to-crossing correspondence)", st.field)
			}
			fields[st.field] = true
			if st.sens == stag.SinkAuthoritative && st.ruleRef == "" && static[st.in] != stag.Authoritative {
				return nil, errf(st.node, "guaranteed deny: authoritative sink %q fed by non-authoritative slot %q with no rule", st.id, st.in)
			}
		}
	}

	// edges: known, strictly forward
	edge := func(st rawStep, target string) error {
		j, ok := idx[target]
		if !ok {
			return errf(st.node, "edge to unknown id %q", target)
		}
		if j <= idx[st.id] {
			return errf(st.node, "backward edge to %q", target)
		}
		return nil
	}
	for _, st := range steps {
		if st.gto != "" {
			if err := edge(st, st.gto); err != nil {
				return nil, err
			}
		}
		for _, c := range st.cases {
			if err := edge(st, c.gto); err != nil {
				return nil, err
			}
		}
		if st.deflt != "" {
			if err := edge(st, st.deflt); err != nil {
				return nil, err
			}
		}
	}

	// reachability over the real edge semantics
	reached := make([]bool, n)
	queue := []int{0}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if i >= n || reached[i] {
			continue
		}
		reached[i] = true
		st := steps[i]
		switch st.kind {
		case stag.NodeBranch:
			for _, c := range st.cases {
				queue = append(queue, idx[c.gto])
			}
			queue = append(queue, idx[st.deflt])
		case stag.NodeExit:
			// a pure terminal: no successors (halts the path)
		default:
			if st.gto != "" {
				queue = append(queue, idx[st.gto])
			} else if i+1 < n {
				queue = append(queue, i+1)
			}
		}
	}
	for i, r := range reached {
		if !r {
			return nil, errf(steps[i].node, "unreachable step %q", steps[i].id)
		}
	}

	// definite assignment: a consumed slot must be defined on EVERY path to its
	// consumer, not merely declared earlier in document order. Eval populates a
	// propose out-slot only when that propose EXECUTES, and a branch/gate/sink
	// on a missing slot Faults/severs; a skipped propose must not leave a reader
	// unpopulated. Runs after reachability, so every step but 0 has a predecessor;
	// forward-only edges make this a single index-order pass.
	succs := func(i int) []int {
		st := steps[i]
		if st.kind == stag.NodeExit {
			return nil // a pure terminal: halts the path, no successor
		}
		if st.kind == stag.NodeBranch {
			out := make([]int, 0, len(st.cases)+1)
			for _, c := range st.cases {
				out = append(out, idx[c.gto])
			}
			return append(out, idx[st.deflt])
		}
		if st.gto != "" { // propose/sink/gate: explicit forward edge...
			return []int{idx[st.gto]}
		}
		if i+1 < n { // ...or fall-through (a gate's pass path; fail halts)
			return []int{i + 1}
		}
		return nil
	}
	preds := make([][]int, n)
	for i := 0; i < n; i++ {
		for _, s := range succs(i) {
			preds[s] = append(preds[s], i)
		}
	}
	exit := make([]map[string]bool, n)
	for j := 0; j < n; j++ {
		entry := map[string]bool{}
		if len(preds[j]) == 0 { // the entry step: ingredients are defined on all paths
			for name := range ingredients {
				entry[name] = true
			}
		} else {
			for i, pI := range preds[j] {
				if i == 0 {
					for k := range exit[pI] {
						entry[k] = true
					}
					continue
				}
				for k := range entry {
					if !exit[pI][k] { // intersection: must-defined
						delete(entry, k)
					}
				}
			}
		}
		st := steps[j]
		if st.kind == stag.NodeSink || st.kind == stag.NodeGate || st.kind == stag.NodeBranch || st.kind == stag.NodeForeach {
			if !entry[st.in] {
				return nil, errf(st.node, "slot %q is not defined on every path to step %q (a branch can skip its producer)", st.in, st.id)
			}
		}
		exit[j] = entry
		if st.kind == stag.NodePropose {
			e2 := map[string]bool{st.out: true}
			for k := range entry {
				e2[k] = true
			}
			exit[j] = e2
		}
		if st.kind == stag.NodeForeach { // foreach defines its element slot on its (body) exit
			e2 := map[string]bool{st.as: true}
			for k := range entry {
				e2[k] = true
			}
			exit[j] = e2
		}
	}

	// gate protection: no explicit edge into a guarded segment
	inSegment := map[string]string{} // step id -> guarding gate id
	for i, st := range steps {
		if st.kind != stag.NodeGate {
			continue
		}
		for j := i + 1; j < n; j++ {
			inSegment[steps[j].id] = st.id
			if steps[j].gto != "" || steps[j].kind == stag.NodeBranch || steps[j].kind == stag.NodeGate || steps[j].kind == stag.NodeExit {
				break // an explicit edge, a branch, a nested gate, or a terminal ends the segment
			}
		}
	}
	checkGuard := func(st rawStep, target string) error {
		if g, guarded := inSegment[target]; guarded {
			return errf(st.node, "edge into guarded segment of gate %q (the only way in is through the gate)", g)
		}
		return nil
	}
	for _, st := range steps {
		if st.gto != "" {
			if err := checkGuard(st, st.gto); err != nil {
				return nil, err
			}
		}
		for _, c := range st.cases {
			if err := checkGuard(st, c.gto); err != nil {
				return nil, err
			}
		}
		if st.deflt != "" {
			if err := checkGuard(st, st.deflt); err != nil {
				return nil, err
			}
		}
	}

	// hygiene warnings (draft mode; strict makes them errors)
	var warns []string
	for name := range ingredients {
		if !usedIngredient[name] {
			warns = append(warns, fmt.Sprintf("unused ingredient %q", name))
		}
	}
	for id := range registry {
		if !usedRule[id] {
			warns = append(warns, fmt.Sprintf("unreferenced rule %q", id))
		}
	}
	sort.Strings(warns)
	return warns, nil
}
