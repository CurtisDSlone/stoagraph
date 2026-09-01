package provider_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

func writeBundle(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A static bundle serves every file verbatim, ignores the query, and stamps untrusted at origin.
func TestStaticServesBundleNoQuery(t *testing.T) {
	dir := writeBundle(t, map[string]string{
		"scale.md":            "to scale: kubectl scale ...",
		"runbooks/isolate.md": "to isolate: cordon the node",
	})
	s, err := provider.NewStatic("runbooks", dir)
	if err != nil {
		t.Fatalf("new static: %v", err)
	}
	// the query is ignored — the whole bundle is the context.
	items, errs := provider.Gather(context.Background(), "anything at all", []provider.ContextProvider{s})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 files, got %d", len(items))
	}
	// sorted by rel-path (deterministic), stamped untrusted.
	if items[0].Source != "runbooks/isolate.md" || items[1].Source != "scale.md" {
		t.Fatalf("files must be sorted by rel-path: %s, %s", items[0].Source, items[1].Source)
	}
	for _, it := range items {
		if it.Trust != provider.Untrusted {
			t.Fatalf("static content must be stamped untrusted; got %q", it.Trust)
		}
	}
}

// The bundle hash is content-addressed: identical content -> identical hash; any edit -> new hash.
func TestStaticBundleHashChangesOnEdit(t *testing.T) {
	files := map[string]string{"a.md": "alpha", "b.md": "beta"}
	dir1 := writeBundle(t, files)
	s1, err := provider.NewStatic("kb", dir1)
	if err != nil {
		t.Fatal(err)
	}
	dir2 := writeBundle(t, files) // same content, different tempdir
	s2, err := provider.NewStatic("kb", dir2)
	if err != nil {
		t.Fatal(err)
	}
	if s1.BundleHash() != s2.BundleHash() {
		t.Fatal("identical content must produce an identical bundle hash (content-addressed)")
	}
	dir3 := writeBundle(t, map[string]string{"a.md": "alpha", "b.md": "beta EDITED"})
	s3, err := provider.NewStatic("kb", dir3)
	if err != nil {
		t.Fatal(err)
	}
	if s1.BundleHash() == s3.BundleHash() {
		t.Fatal("an edited bundle must get a new hash")
	}
}

// CRLF is canonicalized to LF so the hash is stable across platforms.
func TestStaticCanonicalizesLineEndings(t *testing.T) {
	crlf := writeBundle(t, map[string]string{"a.md": "line1\r\nline2\r\n"})
	lf := writeBundle(t, map[string]string{"a.md": "line1\nline2\n"})
	sc, _ := provider.NewStatic("kb", crlf)
	sl, _ := provider.NewStatic("kb", lf)
	if sc.BundleHash() != sl.BundleHash() {
		t.Fatal("CRLF and LF of the same text must hash the same")
	}
}

// Fail closed: an empty bundle, a missing path, and an oversize bundle are registration errors.
func TestStaticFailsClosed(t *testing.T) {
	if _, err := provider.NewStatic("x", writeBundle(t, map[string]string{})); err == nil {
		t.Fatal("empty bundle must error")
	}
	if _, err := provider.NewStatic("x", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing path must error")
	}
	big := writeBundle(t, map[string]string{"huge.md": strings.Repeat("A", provider.MaxBundleBytes+1)})
	if _, err := provider.NewStatic("x", big); err == nil {
		t.Fatal("oversize bundle must error")
	}
}

// FromConfig wires the static kind (and rejects a missing path); rag/mcp_resource stay reserved.
func TestFromConfigStatic(t *testing.T) {
	dir := writeBundle(t, map[string]string{"a.md": "x"})
	p, err := provider.FromConfig("kb", "static", `{"path":"`+dir+`"}`)
	if err != nil {
		t.Fatalf("static from config: %v", err)
	}
	if p.Name() != "kb" {
		t.Fatalf("name = %q", p.Name())
	}
	if _, err := provider.FromConfig("kb", "static", `{}`); err == nil {
		t.Fatal("static without a path must error")
	}
	for _, reserved := range []string{"rag", "mcp_resource"} {
		if _, err := provider.FromConfig("kb", reserved, `{}`); err == nil {
			t.Fatalf("%q must remain reserved (fail closed)", reserved)
		}
	}
}
