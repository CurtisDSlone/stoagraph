// Package recipestore is the recipe-authoring core behind the gate's /api/recipes and the
// -recipes-dir a gate is started with: validate recipe YAML through the REAL parser + linter and
// persist valid recipes. Validate
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

// ServerLookup resolves a registered MCP server by name — the same "server, tool" shape
// /api/routes already validates against (stag/serve/routes.go's GetMCPServer + tool-discovery
// check). A future tools:-map validation step calls this to fail closed against whatever is
// actually registered, instead of trusting a name a recipe merely asserts.
type ServerLookup func(name string) (Server, error)

// Server is the slice of a registered MCP server a recipe-side validation needs: whether it
// exists, and which tools it has discovered. Deliberately NOT store.MCPServer — recipestore
// stays store-agnostic, the same way recipe.Resolver never mentions recipestore.Store.
type Server struct {
	Name  string
	Tools []string // discovered tool names; empty means "discovery has never run" (routes.go's
	//                 own documented edge case: an empty list does not fail a name check closed)
}

// ProviderLookup resolves the set of registered context-provider names — the same list
// /api/providers already serves. A future providers:-map validation step calls this to fail
// closed against whatever is actually registered.
type ProviderLookup func() ([]string, error)

// kw: tier row label verdict tier
type TierRow struct {
	Label   string `json:"label"`
	Verdict string `json:"verdict"`
	Tier    string `json:"tier"`
}

// kw: validate result valid name hash error warnings tiers providers
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
	// Providers is this recipe's own declared READ-channel allowlist (Recipe.Providers) — surfaced
	// so a caller (the dispatcher binding a session for this recipe) can resolve the session's
	// context providers from the recipe itself, the same way it resolves the session's tool routes
	// from RoutesForRecipe. Not derived here; a plain pass-through of what the parser already
	// computed, same as Hash/LeakBits.
	Providers []string `json:"providers,omitempty"`
	// InvokedTools is the advertised name (<server>__<tool>) of every tool this recipe's own
	// invoke/await steps authorize, sorted, deduped. A sequenced sub-tool is deliberately routed
	// to its OWN separate recipe (never the recipe that invokes it — see the invoke/await wiring
	// invariants), so RoutesForRecipe(this recipe's name) alone never returns those sub-tool
	// routes. InvokedTools is what a caller (the dispatcher binding a session for THIS recipe)
	// walks to resolve and union in those routes by tool name instead — the recipe's own steps
	// are the source of truth for which sub-tools a sequence needs, so this can never drift out
	// of sync the way a hand-maintained side list could.
	InvokedTools []string `json:"invokedTools,omitempty"`
}

// kw: store dir file-backed recipes
type Store struct {
	Dir string

	// Servers and Providers are the recipe store's ONLY connection to the config store — plumbing
	// for a future tools:/providers: validation step, not yet called by anything (Validate/Save
	// behavior is unchanged). Both are optional: nil means "no config store to check against,"
	// the same fail-open-on-authoring the store itself already accepts when discovery has never
	// run (routes.go). Function-typed, not a *store.Store field, so recipestore never depends on
	// the SQLite package directly — mirrors how recipe.Resolver never depends on recipestore.
	Servers   ServerLookup
	Providers ProviderLookup
}

// Validate lints a draft with NO composition (a goto_recipe reference errors) and NO config-store
// check (Store{}'s Servers/Providers are both nil, so checkRegistrations is a no-op) — the
// package-level entry for callers without a store. kw: validate parse draft lint tier preview no-panic
func Validate(src []byte) ValidateResult { return Store{}.validate(src, nil) }

// Validate (store method) resolves goto_recipe/default_recipe sub-recipes through the
// store, so a composed recipe lints against its real dependencies. kw: compose resolve store
func (s Store) Validate(src []byte) ValidateResult { return s.validate(src, s.resolver()) }

// resolver adapts the store's name->bytes lookup to the composition resolver.
func (s Store) resolver() recipe.Resolver {
	return func(name string) ([]byte, error) { return s.Get(name) }
}

func (s Store) validate(src []byte, resolve recipe.Resolver) ValidateResult {
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
	// Structural checks (does the recipe make sense on its own) are recipe.Compose's job, above —
	// it never touches the config store. This is the ONE place recipestore adds a check of its
	// own: does what the recipe NAMES actually exist. Deliberately after parsing, not threaded
	// into it — the parser stays store-agnostic (recipe.Resolver only ever resolves OTHER
	// RECIPES), and by this point Recipe.Tools/Recipe.Providers are already plain, fully-resolved
	// data to walk.
	if rerr := s.checkRegistrations(p.Recipe); rerr != nil {
		return ValidateResult{Valid: false, Error: rerr.Error()}
	}
	vr := ValidateResult{Valid: true, Name: p.Header.Name, Hash: p.SemanticHash, Warnings: warns, Providers: p.Recipe.Providers, InvokedTools: invokedTools(p.Recipe)}
	lk := recipe.Leakage(p.Recipe)
	vr.LeakBits, vr.LeakUnbounded, vr.LeakReason = lk.CallBits, lk.Unbounded, lk.UnboundedReason
	for _, label := range vocab(p) {
		res := stag.Eval(p.Recipe, label, p.SemanticHash)
		vr.Tiers = append(vr.Tiers, TierRow{Label: label, Verdict: res.Verdict.String(), Tier: tierName(res)})
	}
	return vr
}

// checkRegistrations fails closed if the recipe's tools: or providers: name something that does
// not actually exist in the config store — a server/provider never registered, or a tool a
// registered server has demonstrably NOT discovered. Both Servers and Providers are optional
// (nil means "no config store to check against," e.g. recipe.Validate's package-level entry, or a
// Store constructed without them): the check is a no-op then, same fail-open-on-authoring the
// store itself already accepts elsewhere in this codebase when there's nothing to check against.
//
// The tool-name half matches routes.go's own precedent exactly, for the identical edge case: a
// server whose Tools list is EMPTY (discovery has never run) cannot prove a tool name is wrong, so
// it does not fail one closed — only a NON-empty list that provably lacks the name does. The
// server itself must still be registered either way; that's never soft.
func (s Store) checkRegistrations(r stag.Recipe) error {
	if s.Servers != nil {
		servers := make([]string, 0, len(r.Tools))
		for srv := range r.Tools {
			servers = append(servers, srv)
		}
		sort.Strings(servers) // deterministic error message regardless of map iteration order
		for _, srv := range servers {
			sv, err := s.Servers(srv)
			if err != nil {
				return fmt.Errorf("tools.%s: server not registered: %w", srv, err)
			}
			if len(sv.Tools) == 0 {
				continue // discovery never ran: cannot prove any tool name under it is wrong
			}
			known := make(map[string]bool, len(sv.Tools))
			for _, t := range sv.Tools {
				known[t] = true
			}
			tools := make([]string, 0, len(r.Tools[srv]))
			for t := range r.Tools[srv] {
				tools = append(tools, t)
			}
			sort.Strings(tools)
			for _, t := range tools {
				if !known[t] {
					return fmt.Errorf("tools.%s.%s: server %q does not expose a tool named %q", srv, t, srv, t)
				}
			}
		}
	}
	if s.Providers != nil && len(r.Providers) > 0 {
		names, err := s.Providers()
		if err != nil {
			return fmt.Errorf("providers: %w", err)
		}
		known := make(map[string]bool, len(names))
		for _, n := range names {
			known[n] = true
		}
		for _, p := range r.Providers {
			if !known[p] {
				return fmt.Errorf("providers: %q is not a registered context provider", p)
			}
		}
	}
	return nil
}

// kw: invoked tools advertised name invoke await dedup sorted
func invokedTools(r stag.Recipe) []string {
	set := map[string]bool{}
	for _, st := range r.Steps {
		if st.Kind == stag.NodeInvoke || st.Kind == stag.NodeAwait {
			set[st.Tool] = true
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
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
