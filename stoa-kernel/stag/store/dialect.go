package store

// file-kw: dialect sqlite postgres dsn rebind placeholders conn txn driver-quarantine backend-select

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

// A dialect is everything that differs between the two databases this store runs on. It is
// deliberately small: the SQL itself is already portable (ON CONFLICT ... DO UPDATE, RETURNING,
// plain TEXT/INTEGER), so what remains is placeholder syntax, column introspection for the schema
// guard, and how to open a connection. The 23 CRUD methods never see it; conn and txn apply it.
type dialect struct {
	name    string
	open    func(dsn string) (*sql.DB, error)
	rebind  func(q string) string
	columns func(ctx context.Context, db *sql.DB, table string) (map[string]bool, error)
}

// IsPostgres reports whether dsn selects the Postgres backend. Callers that treat the store
// argument as a file path (mkdir its parent, print it in a log line) must check this first: a DSN
// has no parent directory to create and carries a password that must not be logged.
func IsPostgres(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// Describe renders dsn for a log line: a SQLite path unchanged, a Postgres DSN with the password
// removed. Nothing in this product should ever print a credential, and the store's own DSN is the
// one most likely to be printed by accident.
func Describe(dsn string) string {
	if !IsPostgres(dsn) {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://<unparseable>"
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.Redacted()
}

func dialectFor(dsn string) dialect {
	if IsPostgres(dsn) {
		return postgres
	}
	return sqlite
}

var sqlite = dialect{
	name: "sqlite",
	open: func(path string) (*sql.DB, error) {
		db, err := sql.Open("sqlite", sqliteDSN(path))
		if err != nil {
			return nil, err
		}
		// SQLite is single-writer; one connection also keeps an in-memory DB consistent.
		db.SetMaxOpenConns(1)
		return db, nil
	},
	rebind: func(q string) string { return q }, // ? is native
	columns: func(ctx context.Context, db *sql.DB, table string) (map[string]bool, error) {
		return scanNames(db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table))
	},
}

var postgres = dialect{
	name: "postgres",
	open: func(dsn string) (*sql.DB, error) {
		return sql.Open("pgx", dsn) // pool defaults; the server's max_connections is the real cap
	},
	rebind: rebind,
	columns: func(ctx context.Context, db *sql.DB, table string) (map[string]bool, error) {
		return scanNames(db.QueryContext(ctx,
			`SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1`, table))
	},
}

// sqliteDSN turns a plain file path into a driver DSN with the two pragmas that make a shared file
// safe for the two processes (stag-serve, stag-proxy) that open it concurrently: WAL so a reader
// never blocks a writer, and a busy_timeout so a writer waits for the other's lock instead of
// failing with SQLITE_BUSY on the first collision. SetMaxOpenConns(1) serializes within a process;
// these serialize across them. A ":memory:" path or a caller-supplied DSN (already has a "?") is
// passed through untouched: WAL is meaningless in memory, and a DSN author owns their own pragmas.
func sqliteDSN(path string) string {
	if strings.HasPrefix(path, ":") || strings.Contains(path, "?") {
		return path
	}
	return path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}

// rebind rewrites ? placeholders to $1..$n. A ? inside a single-quoted literal is left alone; the
// store's SQL has none today, but a rewriter that would corrupt one tomorrow is a trap, not a tool.
func rebind(q string) string {
	if !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n, inLit := 0, false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'':
			inLit = !inLit
			b.WriteByte(c)
		case c == '?' && !inLit:
			n++
			fmt.Fprintf(&b, "$%d", n)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func scanNames(rows *sql.Rows, err error) (map[string]bool, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// conn is the store's handle: a *sql.DB plus its dialect. It exposes exactly the calls the CRUD
// methods make, each rebinding placeholders first, and nothing else, so a query cannot slip past the
// dialect by reaching for a raw method. Not an embedded *sql.DB for that reason.
type conn struct {
	db *sql.DB
	d  dialect
}

func (c *conn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return c.db.ExecContext(ctx, c.d.rebind(q), args...)
}

func (c *conn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return c.db.QueryContext(ctx, c.d.rebind(q), args...)
}

func (c *conn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.db.QueryRowContext(ctx, c.d.rebind(q), args...)
}

func (c *conn) BeginTx(ctx context.Context, opts *sql.TxOptions) (*txn, error) {
	tx, err := c.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &txn{tx: tx, d: c.d}, nil
}

func (c *conn) PingContext(ctx context.Context) error { return c.db.PingContext(ctx) }
func (c *conn) Close() error                          { return c.db.Close() }

// txn mirrors conn inside a transaction.
type txn struct {
	tx *sql.Tx
	d  dialect
}

func (t *txn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, t.d.rebind(q), args...)
}

func (t *txn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, t.d.rebind(q), args...)
}

func (t *txn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, t.d.rebind(q), args...)
}

func (t *txn) Commit() error   { return t.tx.Commit() }
func (t *txn) Rollback() error { return t.tx.Rollback() }
