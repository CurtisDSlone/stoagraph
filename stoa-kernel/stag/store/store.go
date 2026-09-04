// Package store is the SQLite config store for the admin console's Adapters
// (Planning/18): the persisted, RELATIONAL config that the file-based recipes bind
// to — MCP servers (+ their tools), context providers, and routes (tool → recipe →
// gated arg). Persistence only, typed fail-closed CRUD, the whole schema in ONE
// embedded DDL file (store/schema.sql). NO MIGRATIONS: edit the DDL and re-init.
// modernc.org/sqlite (pure Go) is quarantined here; the kernel/gate never import a
// DB driver. All queries are parameterized — arbitrary strings are inert data.
package store

// file-kw: sqlite config store adapters mcp-server context-provider route ddl no-migrations quarantined

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"sort"

	_ "modernc.org/sqlite" // driver "sqlite", quarantined to this package
)

//go:embed schema.sql
var schemaSQL string

// kw: mcp server name transport target enabled tools downstream-auth
type MCPServer struct {
	Name      string
	Transport string
	Target    string
	Enabled   bool
	Tools     []MCPTool
	// Downstream auth (Planning/28): the credential the GATE uses to reach an authenticated HTTP
	// downstream, so the agent never holds it. Credential() resolves Secret (dev) else SecretEnv.
	AuthScheme  string // none | bearer | header | query | oauth
	AuthHeader  string // header scheme: the header name
	Secret      string // dev direct secret
	SecretEnv   string // env var holding the secret (preferred)
	OAuthConfig string // oauth non-secret JSON (v1.1)
}

// Credential resolves the usable downstream secret: stored directly (dev), else the named env var.
func (m MCPServer) Credential() string {
	if m.Secret != "" {
		return m.Secret
	}
	if m.SecretEnv != "" {
		return os.Getenv(m.SecretEnv)
	}
	return ""
}

// kw: mcp tool server name input schema
type MCPTool struct {
	Server      string
	Name        string
	InputSchema string
}

// kw: context provider name kind config enabled
type ContextProvider struct {
	Name    string
	Kind    string
	Config  string
	Enabled bool
}

// kw: route tool recipe gate-arg binding
type Route struct {
	Tool    string
	Server  string // WHICH MCP server serves this tool. The route delegates; the gate never infers.
	Recipe  string
	GateArg string
	// Sequenced: bound ONLY so a recipe's `invoke` may authorize calls to it — not advertised,
	// and unreachable without a one-shot grant. Zero value = an ordinary advertised route, so
	// every existing row keeps its meaning.
	Sequenced bool
}

// kw: store sqlite db handle
type Store struct {
	db *sql.DB
}

// kw: open create run ddl fail-closed no-migrations single-conn
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite is single-writer; one connection also keeps an in-memory DB consistent.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil { // the ONE DDL (no migrations)
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	// NO MIGRATIONS means CREATE TABLE IF NOT EXISTS leaves an OLDER table exactly as it was, so a
	// database written before a column existed opens cleanly and then fails on the first query that
	// names it. A store that starts fine and breaks on first use is the worst failure mode: the
	// operator learns about it from a broken request rather than from startup.
	//
	// So check the columns the current DDL needs and refuse up front, with what to do about it.
	if err := checkSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// checkSchema verifies that pre-existing tables carry the columns this build queries. It names
// the missing column and the remedy, because "no such column" from a live request does neither.
// kw: schema guard no-migrations stale database refuse up-front actionable
func checkSchema(db *sql.DB) error {
	// column -> the DDL type it must have, so the suggested remedy is actually correct: a hint
	// that produces a WRONG column is worse than no hint at all.
	required := map[string]map[string]string{
		"route":               {"sequenced": "INTEGER NOT NULL DEFAULT 0"},
		"authorization_grant": {"session": "TEXT NOT NULL DEFAULT ''"},
	}
	for _, table := range sortedTables(required) {
		have, err := tableColumns(db, table)
		if err != nil {
			return fmt.Errorf("store: inspect %s: %w", table, err)
		}
		if len(have) == 0 {
			continue // the table did not pre-exist; the DDL just created it correctly
		}
		cols := required[table]
		for _, c := range sortedCols(cols) {
			if !have[c] {
				return fmt.Errorf("store: this database predates the %q column on %q. "+
					"The store has no migrations by design: back up the file and re-initialize it, "+
					"or add the column with: ALTER TABLE %s ADD COLUMN %s %s",
					c, table, table, c, cols[c])
			}
		}
	}
	return nil
}

// sortedTables/sortedCols keep the guard's error DETERMINISTIC: Go map iteration is randomized,
// and an operator comparing two runs must not see a different column named each time.
// kw: sorted deterministic guard error
func sortedTables(m map[string]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// kw: sorted columns deterministic
func sortedCols(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// kw: table columns pragma introspect
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
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

// kw: close db
func (s *Store) Close() error { return s.db.Close() }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// kw: put mcp server upsert replace tools transaction atomic
func (s *Store) PutMCPServer(ctx context.Context, srv MCPServer) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — no-op after commit
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO mcp_server(name,transport,target,enabled,auth_scheme,auth_header,secret,secret_env,oauth_config)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET
		   transport=excluded.transport, target=excluded.target, enabled=excluded.enabled,
		   auth_scheme=excluded.auth_scheme, auth_header=excluded.auth_header,
		   secret=CASE WHEN excluded.secret='' THEN mcp_server.secret ELSE excluded.secret END,
		   secret_env=excluded.secret_env, oauth_config=excluded.oauth_config`,
		srv.Name, srv.Transport, srv.Target, boolToInt(srv.Enabled),
		srv.AuthScheme, srv.AuthHeader, srv.Secret, srv.SecretEnv, srv.OAuthConfig); err != nil {
		return fmt.Errorf("store: put server: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_tool WHERE server_name=?`, srv.Name); err != nil {
		return fmt.Errorf("store: clear tools: %w", err)
	}
	for _, tl := range srv.Tools {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO mcp_tool(server_name,name,input_schema) VALUES(?,?,?)`,
			srv.Name, tl.Name, tl.InputSchema); err != nil {
			return fmt.Errorf("store: put tool: %w", err)
		}
	}
	return tx.Commit()
}

// kw: get mcp server with tools not-found fail-closed
func (s *Store) GetMCPServer(ctx context.Context, name string) (MCPServer, error) {
	var srv MCPServer
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT name,transport,target,enabled,auth_scheme,auth_header,secret,secret_env,oauth_config FROM mcp_server WHERE name=?`, name).
		Scan(&srv.Name, &srv.Transport, &srv.Target, &enabled, &srv.AuthScheme, &srv.AuthHeader, &srv.Secret, &srv.SecretEnv, &srv.OAuthConfig)
	if err != nil {
		return MCPServer{}, fmt.Errorf("store: get server %q: %w", name, err)
	}
	srv.Enabled = enabled != 0
	tools, err := s.toolsFor(ctx, name)
	if err != nil {
		return MCPServer{}, err
	}
	srv.Tools = tools
	return srv, nil
}

// kw: tools for server ordered
func (s *Store) toolsFor(ctx context.Context, server string) ([]MCPTool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server_name,name,input_schema FROM mcp_tool WHERE server_name=? ORDER BY name`, server)
	if err != nil {
		return nil, fmt.Errorf("store: tools: %w", err)
	}
	defer rows.Close()
	var out []MCPTool
	for rows.Next() {
		var tl MCPTool
		if err := rows.Scan(&tl.Server, &tl.Name, &tl.InputSchema); err != nil {
			return nil, err
		}
		out = append(out, tl)
	}
	return out, rows.Err()
}

// kw: list mcp servers ordered with tools
func (s *Store) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,transport,target,enabled,auth_scheme,auth_header,secret,secret_env,oauth_config FROM mcp_server ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list servers: %w", err)
	}
	var names []MCPServer
	for rows.Next() {
		var srv MCPServer
		var enabled int
		if err := rows.Scan(&srv.Name, &srv.Transport, &srv.Target, &enabled, &srv.AuthScheme, &srv.AuthHeader, &srv.Secret, &srv.SecretEnv, &srv.OAuthConfig); err != nil {
			rows.Close()
			return nil, err
		}
		srv.Enabled = enabled != 0
		names = append(names, srv)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i := range names {
		tools, err := s.toolsFor(ctx, names[i].Name)
		if err != nil {
			return nil, err
		}
		names[i].Tools = tools
	}
	return names, nil
}

// kw: delete mcp server and tools transaction
func (s *Store) DeleteMCPServer(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_tool WHERE server_name=?`, name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_server WHERE name=?`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// kw: put provider upsert
func (s *Store) PutProvider(ctx context.Context, p ContextProvider) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO context_provider(name,kind,config,enabled) VALUES(?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,config=excluded.config,enabled=excluded.enabled`,
		p.Name, p.Kind, p.Config, boolToInt(p.Enabled))
	if err != nil {
		return fmt.Errorf("store: put provider: %w", err)
	}
	return nil
}

// kw: list providers ordered
func (s *Store) ListProviders(ctx context.Context) ([]ContextProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,kind,config,enabled FROM context_provider ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list providers: %w", err)
	}
	defer rows.Close()
	var out []ContextProvider
	for rows.Next() {
		var p ContextProvider
		var enabled int
		if err := rows.Scan(&p.Name, &p.Kind, &p.Config, &enabled); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// kw: delete provider
func (s *Store) DeleteProvider(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM context_provider WHERE name=?`, name)
	return err
}

// PutRoute upserts a route keyed by (tool, server).
//
// The conflict target is the PAIR. Re-routing `search_code` on `github` updates that binding and
// leaves `search_code` on `local` untouched — where a tool-only conflict target used to overwrite
// server_name and silently move a route the operator never touched.
// kw: put route upsert by tool+server
func (s *Store) PutRoute(ctx context.Context, r Route) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO route(tool_name,server_name,recipe_name,gate_arg,sequenced) VALUES(?,?,?,?,?)
		 ON CONFLICT(tool_name,server_name) DO UPDATE SET recipe_name=excluded.recipe_name,gate_arg=excluded.gate_arg,sequenced=excluded.sequenced`,
		r.Tool, r.Server, r.Recipe, r.GateArg, r.Sequenced)
	if err != nil {
		return fmt.Errorf("store: put route: %w", err)
	}
	return nil
}

// kw: list routes ordered
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tool_name,server_name,recipe_name,gate_arg,sequenced FROM route ORDER BY server_name,tool_name`)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.Tool, &r.Server, &r.Recipe, &r.GateArg, &r.Sequenced); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRoute removes ONE binding, named by both halves of its key. Deleting `search_code` on
// `github` must not disturb `search_code` on `local`, so the tool name alone is not enough to say
// which route the operator meant.
// kw: delete route by tool+server
func (s *Store) DeleteRoute(ctx context.Context, tool, server string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM route WHERE tool_name=? AND server_name=?`, tool, server)
	return err
}
