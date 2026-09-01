// Package recipestore is the recipe-authoring core for the admin console: validate
// recipe YAML through the REAL parser + linter and persist valid recipes. Validate
// returns whether a draft parses, its lint error or warnings, and a tier preview
// (each label evaluated through the kernel to auto/escalate/benign/deny). A
// file-backed Store persists recipes by their (grammar-sanitized) name; Save
// refuses to write an invalid recipe — the store never holds a broken policy.
package recipestore

// file-kw: recipe authoring validate lint tier preview store crud fail-closed no-traversal admin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// kw: tier row label verdict tier
type TierRow struct {
	Label   string `json:"label"`
	Verdict string `json:"verdict"`
	Tier    string `json:"tier"`
}

// kw: validate result valid name hash error warnings tiers
type ValidateResult struct {
	Valid    bool      `json:"valid"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash,omitempty"`
	Error    string    `json:"error,omitempty"`
	Warnings []string  `json:"warnings,omitempty"`
	Tiers    []TierRow `json:"tiers,omitempty"`
	// LeakBits is the choice-channel bound: the max bits a single session could exfiltrate through the
	// agent's choices among what this recipe ALLOWS (see recipe.Leakage). LeakUnbounded is set when a
	// free-text field voids the bound. Shown at authoring time so the operator sees the covert-channel
	// capacity of a policy as they write it — a number no competitor can produce.
	LeakBits      float64 `json:"leakBits"`
	LeakUnbounded bool    `json:"leakUnbounded,omitempty"`
	LeakReason    string  `json:"leakReason,omitempty"`
}

// kw: store dir file-backed recipes
type Store struct {
	Dir string
}

// Validate lints a draft with NO composition (a goto_recipe reference errors). The
// package-level entry for callers without a store. kw: validate parse draft lint tier preview no-panic
func Validate(src []byte) ValidateResult { return validate(src, nil) }

// Validate (store method) resolves goto_recipe/default_recipe sub-recipes through the
// store, so a composed recipe lints against its real dependencies. kw: compose resolve store
func (s Store) Validate(src []byte) ValidateResult { return validate(src, s.resolver()) }

// resolver adapts the store's name->bytes lookup to the composition resolver.
func (s Store) resolver() recipe.Resolver {
	return func(name string) ([]byte, error) { return s.Get(name) }
}

func validate(src []byte, resolve recipe.Resolver) ValidateResult {
	var (
		p     recipe.Parsed
		warns []string
		err   error
	)
	if resolve == nil {
		p, warns, err = recipe.ParseDraft(src)
	} else {
		p, warns, err = recipe.Compose(src, resolve)
	}
	if err != nil {
		return ValidateResult{Valid: false, Error: err.Error()}
	}
	vr := ValidateResult{Valid: true, Name: p.Header.Name, Hash: p.SemanticHash, Warnings: warns}
	lk := recipe.Leakage(p.Recipe)
	vr.LeakBits, vr.LeakUnbounded, vr.LeakReason = lk.CallBits, lk.Unbounded, lk.UnboundedReason
	for _, label := range vocab(p) {
		res := stag.Eval(p.Recipe, label, p.SemanticHash)
		vr.Tiers = append(vr.Tiers, TierRow{Label: label, Verdict: res.Verdict.String(), Tier: tierName(res)})
	}
	return vr
}

// kw: vocab union of rule set members sorted
func vocab(p recipe.Parsed) []string {
	set := map[string]bool{}
	for _, r := range p.Rules {
		for _, m := range r.Set {
			set[m] = true
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// kw: tier name auto benign escalate deny from eval result
func tierName(r stag.EvalResult) string {
	switch {
	case r.Verdict == stag.Allow && len(r.Events) > 0:
		return "auto"
	case r.Verdict == stag.Allow:
		return "benign"
	case r.Verdict == stag.Escalate:
		return "escalate"
	default:
		return "deny"
	}
}

// kw: list all recipes validated sorted
func (s Store) List() ([]ValidateResult, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil // an empty/absent store is not an error
	}
	if err != nil {
		return nil, err
	}
	var out []ValidateResult
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if rerr != nil {
			continue // skip an unreadable file
		}
		out = append(out, s.Validate(b)) // compose against stored sub-recipes
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// kw: get raw bytes name sanitized
func (s Store) Get(name string) ([]byte, error) {
	if !nameOK(name) {
		return nil, fmt.Errorf("invalid recipe name %q", name)
	}
	return os.ReadFile(filepath.Join(s.Dir, name+".yaml"))
}

// kw: save validate then write fail-closed
func (s Store) Save(src []byte) (ValidateResult, error) {
	vr := s.Validate(src) // compose: a parent's sub-recipes must already be stored
	if !vr.Valid {
		return vr, fmt.Errorf("recipe does not parse, not saved: %s", vr.Error) // fail closed
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return vr, err
	}
	// vr.Name is the parser-validated recipe identifier (lowercase/digits/_, max 64),
	// so it cannot escape Dir; guard anyway.
	if !nameOK(vr.Name) {
		return vr, fmt.Errorf("recipe name %q is not a safe identifier", vr.Name)
	}
	return vr, os.WriteFile(filepath.Join(s.Dir, vr.Name+".yaml"), src, 0o644)
}

// kw: delete name sanitized
func (s Store) Delete(name string) error {
	if !nameOK(name) {
		return fmt.Errorf("invalid recipe name %q", name)
	}
	return os.Remove(filepath.Join(s.Dir, name+".yaml"))
}

// kw: name ok recipe identifier grammar no traversal
func nameOK(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
