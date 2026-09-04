package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// RANKING IS WHAT MAKES A LOW k SAFE. Returning 2 of 13 matches is only useful if they are the
// right 2 — an unranked bound returns whichever two sorted first, confidently and wrongly.
//
// Measured on the k8s runbook corpus before ranking: the query "drain" matched 13 of 15 files
// and the first two alphabetically were `control-plane.md` and `cordon-vs-drain.md`. The document
// actually about draining a node ranked third by luck.

func rankDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	files := map[string]string{
		// the document that IS about draining
		"drain-node.md": "# Draining a node\nCordon first, then drain, then verify the node is " +
			"empty. A drain that reported success is not a node with no pods on it.",
		// mentions drain once, in passing
		"control-plane.md": "# Control-plane nodes\nA control-plane node runs the API server. " +
			"Do not drain one as routine maintenance.",
		// mentions drain a few times but is about something else
		"pdb-blocking.md": "# PDB blocking an eviction\nA drain sits and does nothing. The budget " +
			"refuses the eviction. Scale up before you drain.",
		// does not mention it at all
		"rollout-stuck.md": "# A rollout is stuck\nUP-TO-DATE is below DESIRED and not moving.",
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// The document whose TITLE and FILENAME are about the query ranks first, not the one that sorts
// first alphabetically.
func TestRankingPutsTheOnAboutItFirst(t *testing.T) {
	s, err := NewStatic("rb", rankDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.Provide(context.Background(), "drain")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("no matches")
	}
	if items[0].Source != "drain-node.md" {
		t.Errorf("the document about draining must rank first, got %q (order: %v)",
			items[0].Source, sources(items))
	}
	// and alphabetical-first must NOT win by default
	if items[0].Source == "control-plane.md" {
		t.Error("ranking is still alphabetical")
	}
}

// A document that does not mention the query at all is not returned.
func TestRankingExcludesNonMatches(t *testing.T) {
	s, err := NewStatic("rb", rankDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, _ := s.Provide(context.Background(), "drain")
	for _, it := range items {
		if it.Source == "rollout-stuck.md" {
			t.Error("a document that never mentions the query must not be returned")
		}
	}
}

// Ranking is DETERMINISTIC: the same query returns the same order every time. An audit that
// records what was served must be replayable, which a scoring function can promise and an
// embedding model cannot.
func TestRankingIsDeterministic(t *testing.T) {
	s, err := NewStatic("rb", rankDir(t))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.Provide(context.Background(), "drain")
	for i := 0; i < 20; i++ {
		got, _ := s.Provide(context.Background(), "drain")
		if len(got) != len(first) {
			t.Fatalf("run %d: length changed", i)
		}
		for j := range got {
			if got[j].Source != first[j].Source {
				t.Fatalf("run %d: order changed at %d: %v vs %v", i, j, sources(got), sources(first))
			}
		}
	}
}

// Equal scores break ties by path, so the order is stable rather than map-iteration order.
func TestEqualScoresBreakTiesByPath(t *testing.T) {
	d := t.TempDir()
	for _, n := range []string{"b.md", "a.md", "c.md"} {
		if err := os.WriteFile(filepath.Join(d, n), []byte("term"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewStatic("rb", d)
	if err != nil {
		t.Fatal(err)
	}
	items, _ := s.Provide(context.Background(), "term")
	if len(items) != 3 {
		t.Fatalf("want 3, got %d", len(items))
	}
	if items[0].Source != "a.md" || items[1].Source != "b.md" || items[2].Source != "c.md" {
		t.Errorf("ties must break by path: %v", sources(items))
	}
}

// A multi-word query scores on its terms, so "drain node" finds the drain document rather than
// requiring that exact phrase to appear.
func TestMultiTermQuery(t *testing.T) {
	s, err := NewStatic("rb", rankDir(t))
	if err != nil {
		t.Fatal(err)
	}
	items, _ := s.Provide(context.Background(), "drain node")
	if len(items) == 0 {
		t.Fatal("a multi-term query must match")
	}
	if items[0].Source != "drain-node.md" {
		t.Errorf("want drain-node.md first, got %v", sources(items))
	}
}

func sources(items []ContextItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Source)
	}
	return out
}
