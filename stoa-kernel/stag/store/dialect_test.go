package store

// Internal tests: reach the dialect seam and s.db directly.

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDialectSelection(t *testing.T) {
	for dsn, want := range map[string]string{
		"data/config.db":                     "sqlite",
		":memory:":                           "sqlite",
		"file:x.db?mode=ro":                  "sqlite",
		"postgres://u:p@h:5432/db":           "postgres",
		"postgresql://u@h/db?sslmode=verify": "postgres",
	} {
		if got := dialectFor(dsn).name; got != want {
			t.Errorf("dialectFor(%q) = %s, want %s", dsn, got, want)
		}
	}
}

func TestDescribeNeverPrintsAPassword(t *testing.T) {
	got := Describe("postgres://stag:hunter2@db.internal:5432/stag?sslmode=require")
	if contains(got, "hunter2") {
		t.Fatalf("password leaked into log text: %s", got)
	}
	if !contains(got, "stag@db.internal") || !contains(got, "/stag") {
		t.Fatalf("redaction must keep the useful parts: %s", got)
	}
	if got := Describe("data/config.db"); got != "data/config.db" {
		t.Fatalf("sqlite path must pass through: %s", got)
	}
}

func TestRebind(t *testing.T) {
	cases := map[string]string{
		`SELECT 1`:                    `SELECT 1`,
		`WHERE a=? AND b=?`:           `WHERE a=$1 AND b=$2`,
		`VALUES(?,?,?)`:               `VALUES($1,$2,$3)`,
		`WHERE note='what?' AND id=?`: `WHERE note='what?' AND id=$1`,
		`DELETE FROM g WHERE f = ? AND s = ? RETURNING f`: `DELETE FROM g WHERE f = $1 AND s = $2 RETURNING f`,
	}
	for in, want := range cases {
		if got := rebind(in); got != want {
			t.Errorf("rebind(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestSQLiteDSNPassthrough(t *testing.T) {
	for _, p := range []string{":memory:", "file:x.db?mode=ro", "x.db?_pragma=foo(1)"} {
		if got := sqliteDSN(p); got != p {
			t.Errorf("sqliteDSN(%q) = %q, want unchanged", p, got)
		}
	}
	want := "data/config.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if got := sqliteDSN("data/config.db"); got != want {
		t.Fatalf("sqliteDSN = %q, want %q", got, want)
	}
}

// A malformed _pragma is silently ignored by the driver, so "Open succeeded" is not evidence WAL
// is on. Ask the database.
func TestOpenEngagesWALAndBusyTimeout(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	if err := s.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var timeout int
	if err := s.db.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", timeout)
	}
	if s.Driver() != "sqlite" {
		t.Fatalf("Driver() = %q", s.Driver())
	}
}

func TestOpenMemoryStillWorks(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	if err := s.db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "memory" {
		t.Fatalf("journal_mode = %q, want memory (pragmas must not be applied to :memory:)", mode)
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
