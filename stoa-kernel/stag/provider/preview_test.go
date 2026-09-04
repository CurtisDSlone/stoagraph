package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A read is finite: one named source, and a closed set of permitted queries. So what it will
// fetch is knowable BEFORE it runs — which is the one thing generic retrieval cannot offer.

func previewDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for n, b := range map[string]string{
		"drain-node.md":    "# Draining a node\ncordon, drain, verify, uncordon",
		"pdb-blocking.md":  "# PDB blocking\nthe budget refuses the eviction",
		"rollout-stuck.md": "# A rollout is stuck\nup-to-date below desired",
	} {
		if err := os.WriteFile(filepath.Join(d, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestPreviewEnumeratesEveryPermittedQuery(t *testing.T) {
	s, err := NewStatic("rb", previewDir(t))
	if err != nil {
		t.Fatal(err)
	}
	rows := Preview(context.Background(), s, []string{"drain", "rollout"})
	if len(rows) != 2 {
		t.Fatalf("one row per permitted query: %d", len(rows))
	}
	for _, r := range rows {
		if r.Empty || len(r.Sources) == 0 {
			t.Errorf("%q retrieved nothing: %+v", r.Query, r)
		}
	}
}

// THE FAILURE THIS EXISTS FOR: a query the author permitted that retrieves nothing. The policy
// promises context and silently delivers none, and nothing at runtime tells them apart.
func TestPreviewSurfacesAPermittedQueryThatRetrievesNothing(t *testing.T) {
	s, err := NewStatic("rb", previewDir(t))
	if err != nil {
		t.Fatal(err)
	}
	rows := Preview(context.Background(), s, []string{"drain", "backup-restore"})
	var empty []string
	for _, r := range rows {
		if r.Empty {
			empty = append(empty, r.Query)
		}
	}
	if len(empty) != 1 || empty[0] != "backup-restore" {
		t.Errorf("a permitted query with no corpus behind it must be visible: %+v", rows)
	}
}

// The preview reflects the SAME bounds a real read applies — a preview showing more than the
// agent would receive is worse than no preview.
func TestPreviewAppliesTheReadBounds(t *testing.T) {
	t.Setenv("STOA_READ_K", "1")
	s, err := NewStatic("rb", previewDir(t))
	if err != nil {
		t.Fatal(err)
	}
	rows := Preview(context.Background(), s, []string{"drain"})
	if len(rows) != 1 || len(rows[0].Sources) != 1 {
		t.Errorf("preview must apply k: %+v", rows)
	}
	if rows[0].Matched < 1 {
		t.Error("and must report how many matched before the bound")
	}
}

// Deterministic and de-duplicated, so two runs of the same recipe preview identically.
func TestPreviewIsStable(t *testing.T) {
	s, err := NewStatic("rb", previewDir(t))
	if err != nil {
		t.Fatal(err)
	}
	a := Preview(context.Background(), s, []string{"rollout", "drain", "drain"})
	b := Preview(context.Background(), s, []string{"drain", "rollout"})
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("duplicates must collapse: %d, %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Query != b[i].Query || len(a[i].Sources) != len(b[i].Sources) {
			t.Errorf("preview is not stable: %+v vs %+v", a, b)
		}
	}
}
