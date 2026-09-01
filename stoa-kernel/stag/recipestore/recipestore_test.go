package recipestore_test

import (
	"bytes"
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
