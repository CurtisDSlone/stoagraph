package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// The store is explicitly NO-MIGRATIONS ("edit the DDL and re-init"). Adding a column to an
// existing table therefore does NOT happen on its own: CREATE TABLE IF NOT EXISTS leaves an
// older table untouched, and every query naming the new column then fails at RUNTIME.
//
// A store that opens cleanly and fails on first use is the worst of both worlds — the operator
// learns about it from a broken request, not from startup. So Open must REFUSE a database whose
// route table predates `sequenced`, and say what to do about it.
func TestOpenRefusesARouteTableMissingSequenced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// build a database with the PRE-sequenced route table
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE route (
		tool_name TEXT NOT NULL, server_name TEXT NOT NULL,
		recipe_name TEXT NOT NULL, gate_arg TEXT NOT NULL,
		PRIMARY KEY (tool_name, server_name))`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatal("Open must refuse a database whose route table predates `sequenced`")
	}
	// and it must be actionable, not just an SQL error
	if got := err.Error(); got == "" || !contains(got, "sequenced") {
		t.Errorf("the error must name the missing column: %v", err)
	}
}

// A fresh database is unaffected.
func TestOpenAcceptsAFreshDatabase(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatalf("a fresh database must open: %v", err)
	}
	defer s.Close()
	if _, err := s.ListRoutes(context.Background()); err != nil {
		t.Errorf("and its route table must be queryable: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
