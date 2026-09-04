package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A `read` step GATES the outbound query, so a provider that silently discards it would make the
// policy appear to bound something with no effect. Static must either use the query or say it
// did not — the one thing it must not do is stay quiet.

func staticDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range map[string]string{
		"drain.md":   "# Draining\ncordon the node before you drain it",
		"rollout.md": "# Rollouts\nwatch the error rate after a promote",
		"index.md":   "# Index\nrunbooks for maintenance",
	} {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// An EMPTY query returns the whole bundle — the existing behaviour, unchanged.
func TestStaticEmptyQueryReturnsEverything(t *testing.T) {
	s, err := NewStatic("rb", staticDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.Provide(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Errorf("an unqueried bundle is the whole bundle: %d items", len(items))
	}
}

// A query SELECTS. Whole-bundle-always makes a gated query meaningless and puts an entire corpus
// into the model's context on every read.
func TestStaticQuerySelects(t *testing.T) {
	s, err := NewStatic("rb", staticDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.Provide(context.Background(), "drain")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("a matching query must return something")
	}
	if len(items) == 3 {
		t.Error("a query must narrow the bundle, not return all of it")
	}
	for _, it := range items {
		if !strings.Contains(strings.ToLower(it.Source+it.Text), "drain") {
			t.Errorf("returned an item unrelated to the query: %s", it.Source)
		}
	}
}

// A query matching NOTHING is an honest empty read, not a silent whole-bundle fallback: falling
// back would return everything precisely when the policy narrowed the question most.
func TestStaticNoMatchIsEmptyNotEverything(t *testing.T) {
	s, err := NewStatic("rb", staticDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.Provide(context.Background(), "kubernetes-federation-topology")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("no match must be an empty read, got %d items", len(items))
	}
}

// Matching is case-insensitive: an author writing "Drain" in a rule should not miss "drain".
func TestStaticMatchIsCaseInsensitive(t *testing.T) {
	s, err := NewStatic("rb", staticDir(t))
	if err != nil {
		t.Fatal(err)
	}
	lower, _ := s.Provide(context.Background(), "drain")
	upper, _ := s.Provide(context.Background(), "DRAIN")
	if len(lower) != len(upper) || len(lower) == 0 {
		t.Errorf("case must not change the result: %d vs %d", len(lower), len(upper))
	}
}
