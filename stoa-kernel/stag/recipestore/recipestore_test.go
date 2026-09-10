package recipestore_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
)

const goodRecipe = `recipe: write_note_policy
version: 1
rules:
  note.allowed:
    kind: set_membership
    set: ["hello", "status-ok", "deploy-done"]
steps:
  - id: propose_text
    kind: propose
    out: text
  - id: apply
    kind: sink
    in: text
    field: mcp.write_note.text
    sensitivity: authoritative
    rule: note.allowed
    actor: "policy:mcp_proxy"
`

// broken: a ruled sink with no actor (the linter rejects this).
const brokenRecipe = `recipe: broken_policy
version: 1
rules:
  r.x:
    kind: set_membership
    set: ["a"]
steps:
  - id: p
    kind: propose
    out: v
  - id: s
    kind: sink
    in: v
    field: mcp.x.v
    sensitivity: authoritative
    rule: r.x
`

func TestValidateGood(t *testing.T) {
	vr := recipestore.Validate([]byte(goodRecipe))
	if !vr.Valid || vr.Name != "write_note_policy" || vr.Hash == "" || vr.Error != "" {
		t.Fatalf("good recipe: %+v", vr)
	}
	if len(vr.Tiers) != 3 {
		t.Fatalf("tier preview: want 3 labels, got %d (%+v)", len(vr.Tiers), vr.Tiers)
	}
	for _, tr := range vr.Tiers {
		if tr.Verdict != "allow" || tr.Tier != "auto" {
			t.Errorf("allowed label should be auto/allow: %+v", tr)
		}
	}
}

func TestValidateBad(t *testing.T) {
	vr := recipestore.Validate([]byte(brokenRecipe))
	if vr.Valid || vr.Error == "" {
		t.Errorf("broken recipe must be invalid with an error: %+v", vr)
	}
	if vr.Name != "" || len(vr.Tiers) != 0 {
		t.Errorf("invalid recipe carries no name/tiers: %+v", vr)
	}
	// must not panic on junk
	_ = recipestore.Validate(nil)
	_ = recipestore.Validate([]byte("\xff\x00 garbage {{{"))
}

func TestSaveGetRoundTrip(t *testing.T) {
	s := recipestore.Store{Dir: t.TempDir()}
	vr, err := s.Save([]byte(goodRecipe))
	if err != nil || !vr.Valid || vr.Name != "write_note_policy" {
		t.Fatalf("save: %+v err=%v", vr, err)
	}
	got, err := s.Get("write_note_policy")
	if err != nil || !bytes.Equal(got, []byte(goodRecipe)) {
		t.Fatalf("get round-trip: err=%v equal=%v", err, bytes.Equal(got, []byte(goodRecipe)))
	}
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0].Name != "write_note_policy" {
		t.Fatalf("list: %+v err=%v", list, err)
	}
}

func TestSaveFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := recipestore.Store{Dir: dir}
	vr, err := s.Save([]byte(brokenRecipe))
	if err == nil || vr.Valid {
		t.Errorf("saving a broken recipe must fail: %+v err=%v", vr, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("an invalid recipe must not be written: %v", entries)
	}
}

func TestNameSanitized(t *testing.T) {
	s := recipestore.Store{Dir: t.TempDir()}
	for _, bad := range []string{"../../etc/passwd", "a/b", "..", "", "Has-Caps", "space x"} {
		if _, err := s.Get(bad); err == nil {
			t.Errorf("Get(%q) must reject an invalid name", bad)
		}
		if err := s.Delete(bad); err == nil {
			t.Errorf("Delete(%q) must reject an invalid name", bad)
		}
	}
	// a valid-but-absent name is an error, not a panic
	if _, err := s.Get("not_here"); err == nil {
		t.Error("Get of an absent recipe must error")
	}
}

func TestList(t *testing.T) {
	// empty/absent dir
	empty := recipestore.Store{Dir: filepath.Join(t.TempDir(), "nope")}
	if l, err := empty.List(); err != nil || len(l) != 0 {
		t.Errorf("empty store: %v err=%v", l, err)
	}
	s := recipestore.Store{Dir: t.TempDir()}
	if _, err := s.Save([]byte(goodRecipe)); err != nil {
		t.Fatal(err)
	}
	second := bytes.Replace([]byte(goodRecipe), []byte("write_note_policy"), []byte("aaa_first"), 1)
	if _, err := s.Save(second); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List()
	if len(list) != 2 || list[0].Name != "aaa_first" {
		t.Errorf("list sorted by name: %+v", list)
	}
}

// TestServersProvidersUnusedByDefault proves the plumbing is inert until something calls it:
// Validate/Save behave identically on a Store with no Servers/Providers set (the zero value,
// what every real deployment has today) as on one they're never referenced on.
func TestServersProvidersUnusedByDefault(t *testing.T) {
	s := recipestore.Store{Dir: t.TempDir()}
	vr, err := s.Save([]byte(goodRecipe))
	if err != nil || !vr.Valid {
		t.Fatalf("Save with nil Servers/Providers must behave exactly as before: %+v err=%v", vr, err)
	}
}

// TestServersLookup proves the resolver SHAPE works end to end against a hand-built config-store
// stand-in — the same shape cmd/stag-serve and cmd/stag-proxy wire against the real SQLite store.
// Nothing in recipestore calls this yet (see the comment above); this only proves the field is
// callable and returns what it's given.
func TestServersLookup(t *testing.T) {
	reg := map[string]recipestore.Server{
		"k8stools": {Name: "k8stools", Tools: []string{"set_config", "restart_workload"}},
	}
	s := recipestore.Store{
		Dir: t.TempDir(),
		Servers: func(name string) (recipestore.Server, error) {
			sv, ok := reg[name]
			if !ok {
				return recipestore.Server{}, fmt.Errorf("unknown MCP server: %s", name)
			}
			return sv, nil
		},
	}
	sv, err := s.Servers("k8stools")
	if err != nil || sv.Name != "k8stools" || len(sv.Tools) != 2 {
		t.Fatalf("Servers(%q): %+v err=%v", "k8stools", sv, err)
	}
	if _, err := s.Servers("ghost"); err == nil {
		t.Error("an unregistered server must error, not fabricate a result")
	}
}

// TestProvidersLookup mirrors TestServersLookup for the flat provider list.
func TestProvidersLookup(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Providers: func() ([]string, error) {
			return []string{"runbooks", "changelog"}, nil
		},
	}
	names, err := s.Providers()
	if err != nil || len(names) != 2 {
		t.Fatalf("Providers(): %+v err=%v", names, err)
	}
}

// toolsRecipe names one server/tool under tools: — the shape checkRegistrations validates against
// the config store. No passthrough needed for these tests; k8stools.set_config is enough surface.
const toolsRecipe = `recipe: uses_k8stools
version: 1
tools:
  k8stools:
    set_config: {}
rules:
  key.allowed: {kind: set_membership, set: ["log_level"]}
steps:
  - {id: p, kind: propose, out: key}
  - {id: s, kind: sink, in: key, field: k8stools.set_config.key, sensitivity: authoritative, rule: key.allowed, actor: "policy:x"}
`

// providersRecipe names one provider under providers:, read by its one step.
const providersRecipe = `recipe: uses_runbooks
version: 1
providers: ["runbooks"]
rules:
  topic.allowed: {kind: set_membership, set: ["drain"]}
steps:
  - {id: p, kind: propose, out: topic}
  - {id: rd, kind: read, provider: runbooks, query: {slot: topic, rule: topic.allowed}}
`

// a trigger recipe whose whole job is authorizing a two-step sequence on OTHER recipes' tools —
// no propose/sink/gate of its own, matching the real "invoke-only" shape that surfaced the gap.
const invokeOnlyRecipe = `recipe: drain_sequence
version: 1
rules:
  node.worker: {kind: set_membership, set: ["kind-worker"]}
steps:
  - {id: p_node, kind: propose, out: node}
  - {id: cordon, kind: invoke, tool: k8s__cordon_node,
     args: {node: {slot: node, rule: node.worker}}, actor: "policy:maint"}
  - {id: verify, kind: await, tool: k8s__pods_on_node,
     args: {node: {slot: node, rule: node.worker}},
     until: node.worker, attempts: 3, every_ms: 1000, actor: "policy:maint"}
`

// TestCheckRegistrationsToolsPass: a registered server whose discovered tools include the named
// one validates clean.
func TestCheckRegistrationsToolsPass(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Servers: func(name string) (recipestore.Server, error) {
			if name != "k8stools" {
				return recipestore.Server{}, fmt.Errorf("unknown MCP server: %s", name)
			}
			return recipestore.Server{Name: "k8stools", Tools: []string{"set_config", "restart_workload"}}, nil
		},
	}
	vr := s.Validate([]byte(toolsRecipe))
	if !vr.Valid || vr.Error != "" {
		t.Fatalf("a registered server exposing the named tool must validate: %+v", vr)
	}
}

// TestCheckRegistrationsUnregisteredServerFails: the server itself is never registered — this is
// never soft, regardless of tool-discovery state.
func TestCheckRegistrationsUnregisteredServerFails(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Servers: func(name string) (recipestore.Server, error) {
			return recipestore.Server{}, fmt.Errorf("unknown MCP server: %s", name)
		},
	}
	vr := s.Validate([]byte(toolsRecipe))
	if vr.Valid {
		t.Fatal("a tools: entry naming an unregistered server must fail closed")
	}
}

// TestCheckRegistrationsUndiscoveredToolsSoftPass mirrors routes.go's own documented precedent:
// a server that IS registered but whose Tools list is empty (discovery never ran) cannot prove any
// tool name under it is wrong, so it does not fail one closed.
func TestCheckRegistrationsUndiscoveredToolsSoftPass(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Servers: func(name string) (recipestore.Server, error) {
			return recipestore.Server{Name: name}, nil // registered, but Tools is empty
		},
	}
	vr := s.Validate([]byte(toolsRecipe))
	if !vr.Valid {
		t.Fatalf("an undiscovered (empty Tools) server must soft-pass, matching routes.go: %+v", vr)
	}
}

// TestCheckRegistrationsUnknownToolFails: the server IS registered and HAS discovered tools, but
// not the one this recipe names — this is the provable-wrong case, and must fail closed.
func TestCheckRegistrationsUnknownToolFails(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Servers: func(name string) (recipestore.Server, error) {
			return recipestore.Server{Name: name, Tools: []string{"get_pods"}}, nil // NOT set_config
		},
	}
	vr := s.Validate([]byte(toolsRecipe))
	if vr.Valid {
		t.Fatal("a tools: entry naming a tool the server demonstrably does not expose must fail closed")
	}
}

// TestCheckRegistrationsProvidersPass: a registered provider validates clean.
func TestCheckRegistrationsProvidersPass(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Providers: func() ([]string, error) {
			return []string{"runbooks", "changelog"}, nil
		},
	}
	vr := s.Validate([]byte(providersRecipe))
	if !vr.Valid || vr.Error != "" {
		t.Fatalf("a registered provider must validate: %+v", vr)
	}
}

// TestCheckRegistrationsUnregisteredProviderFails: a providers: entry naming a provider that
// simply is not registered fails closed — no soft-pass equivalent for providers (there's no
// per-provider "discovery" state to be silent about the way tools have).
func TestCheckRegistrationsUnregisteredProviderFails(t *testing.T) {
	s := recipestore.Store{
		Dir: t.TempDir(),
		Providers: func() ([]string, error) {
			return []string{"changelog"}, nil // NOT runbooks
		},
	}
	vr := s.Validate([]byte(providersRecipe))
	if vr.Valid {
		t.Fatal("a providers: entry naming an unregistered provider must fail closed")
	}
}

// TestCheckRegistrationsNoopWhenNil: with Servers/Providers unset (the zero value — every real
// deployment before this feature is adopted), a recipe naming tools/providers that don't exist
// ANYWHERE still validates — there is nothing to check against, so nothing is checked. This is
// the same "no config store" fail-open-on-authoring the rest of the store already accepts.
func TestCheckRegistrationsNoopWhenNil(t *testing.T) {
	s := recipestore.Store{Dir: t.TempDir()}
	if vr := s.Validate([]byte(toolsRecipe)); !vr.Valid {
		t.Fatalf("nil Servers must not check anything: %+v", vr)
	}
	if vr := s.Validate([]byte(providersRecipe)); !vr.Valid {
		t.Fatalf("nil Providers must not check anything: %+v", vr)
	}
}

func FuzzValidate(f *testing.F) {
	f.Add([]byte(goodRecipe))
	f.Add([]byte(brokenRecipe))
	f.Add([]byte(""))
	f.Add([]byte("\xff\x00\x0a recipe: x"))
	f.Fuzz(func(t *testing.T, src []byte) {
		vr := recipestore.Validate(src)

		// (1) Valid iff ParseDraft succeeds — the same oracle, no panic
		_, _, err := recipe.ParseDraft(src)
		if vr.Valid != (err == nil) {
			t.Fatalf("Valid=%v but ParseDraft err=%v for %q", vr.Valid, err, src)
		}
		if vr.Valid && vr.Name == "" {
			t.Fatalf("valid recipe must have a name: %q", src)
		}

		// (2) Save writes a file IFF valid (invalid never persisted)
		dir := t.TempDir()
		s := recipestore.Store{Dir: dir}
		_, serr := s.Save(src)
		entries, _ := os.ReadDir(dir)
		wrote := len(entries) > 0
		if wrote != vr.Valid {
			t.Fatalf("Save wrote=%v but Valid=%v for %q", wrote, vr.Valid, src)
		}
		if vr.Valid && serr != nil {
			t.Fatalf("valid recipe Save errored: %v", serr)
		}
	})
}

// TestInvokedToolsListsSequenceSteps proves the fix for the invoke-only-recipe gap: a recipe whose
// whole job is authorizing invoke/await steps on other recipes' tools must surface those tool
// names so a caller (the dispatcher binding a session for this recipe) can resolve and union in
// their routes — RoutesForRecipe(this recipe's name) alone never returns them, since a sequenced
// sub-tool is deliberately routed to its OWN separate recipe, never this one.
func TestInvokedToolsListsSequenceSteps(t *testing.T) {
	vr := recipestore.Validate([]byte(invokeOnlyRecipe))
	if !vr.Valid {
		t.Fatalf("invokeOnlyRecipe must validate: %s", vr.Error)
	}
	want := []string{"k8s__cordon_node", "k8s__pods_on_node"}
	if len(vr.InvokedTools) != len(want) {
		t.Fatalf("InvokedTools = %v, want %v", vr.InvokedTools, want)
	}
	for i, w := range want {
		if vr.InvokedTools[i] != w {
			t.Errorf("InvokedTools[%d] = %q, want %q", i, vr.InvokedTools[i], w)
		}
	}
}

// TestInvokedToolsEmptyWhenNoSequence: a plain propose/sink recipe with no invoke/await steps
// reports no invoked tools — the field is additive, not a required declaration.
func TestInvokedToolsEmptyWhenNoSequence(t *testing.T) {
	vr := recipestore.Validate([]byte(goodRecipe))
	if !vr.Valid {
		t.Fatalf("goodRecipe must validate: %s", vr.Error)
	}
	if len(vr.InvokedTools) != 0 {
		t.Errorf("InvokedTools = %v, want empty", vr.InvokedTools)
	}
}
