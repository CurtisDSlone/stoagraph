package store_test

// Integration test against a REAL Postgres. Skipped unless STAG_TEST_PG_DSN is set; tools/pg-store-test.sh
// boots a throwaway local server and runs this. It exercises every statement family the store
// uses (upsert with ON CONFLICT + excluded, DELETE ... RETURNING, multi-statement transactions,
// bool<->INTEGER columns) and the two properties that must hold on ANY backend: one-shot grants
// redeem exactly once under contention, and the schema guard refuses a stale table.

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

const pgTables = `DROP TABLE IF EXISTS mcp_server, mcp_tool, context_provider, route, approval, authorization_grant, session`

// pgOpen wipes the schema and opens a fresh store, so each test starts from the DDL.
func pgOpen(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("STAG_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("STAG_TEST_PG_DSN not set; run tools/pg-store-test.sh")
	}
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(pgTables); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	_ = raw.Close()
	s, err := store.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.Driver() != "postgres" {
		t.Fatalf("Driver() = %q, want postgres", s.Driver())
	}
	return s
}

func TestPostgresServersProvidersRoutes(t *testing.T) {
	s := pgOpen(t)
	ctx := context.Background()

	srv := store.MCPServer{Name: "gh", Transport: "http", Target: "https://x", Enabled: true,
		AuthScheme: "bearer", Secret: "s3cret", Tools: []store.MCPTool{{Server: "gh", Name: "search"}, {Server: "gh", Name: "read"}}}
	if err := s.PutMCPServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	// Upsert with an EMPTY secret must keep the stored one (the CASE WHEN excluded.secret='' branch).
	srv.Secret, srv.Enabled, srv.Tools = "", false, srv.Tools[:1]
	if err := s.PutMCPServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMCPServer(ctx, "gh")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "s3cret" || got.Enabled || len(got.Tools) != 1 || got.Tools[0].Name != "search" {
		t.Fatalf("upsert semantics differ on postgres: %+v", got)
	}
	if _, err := s.GetMCPServer(ctx, "nope"); err == nil {
		t.Fatal("missing server must be an error (fail closed)")
	}

	if err := s.PutProvider(ctx, store.ContextProvider{Name: "kb", Kind: "rag", Config: "{}", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ps, err := s.ListProviders(ctx)
	if err != nil || len(ps) != 1 || !ps[0].Enabled {
		t.Fatalf("providers: %v %+v", err, ps)
	}

	// bool -> INTEGER on write, INTEGER -> bool on read, both values.
	for _, r := range []store.Route{
		{Tool: "search", Server: "gh", Recipe: "r1", GateArg: "q", Sequenced: false},
		{Tool: "read", Server: "gh", Recipe: "r2", GateArg: "path", Sequenced: true},
	} {
		if err := s.PutRoute(ctx, r); err != nil {
			t.Fatalf("put route %+v: %v", r, err)
		}
	}
	rs, err := s.ListRoutes(ctx)
	if err != nil || len(rs) != 2 {
		t.Fatalf("routes: %v %+v", err, rs)
	}
	// ORDER BY server_name,tool_name: "read" (sequenced) sorts before "search" (advertised).
	if rs[0].Tool != "read" || !rs[0].Sequenced || rs[1].Tool != "search" || rs[1].Sequenced {
		t.Fatalf("sequenced round-trip lost: %+v", rs)
	}
	if err := s.DeleteRoute(ctx, "read", "gh"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMCPServer(ctx, "gh"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListMCPServers(ctx); len(list) != 0 {
		t.Fatalf("server not deleted: %+v", list)
	}
}

func TestPostgresApprovalLifecycle(t *testing.T) {
	s := pgOpen(t)
	ctx := context.Background()
	created, err := s.RecordPending(ctx, "id1", "deploy", "fp1", `{"a":1}`, "r", "h")
	if err != nil || !created {
		t.Fatalf("first pending: %v created=%v", err, created)
	}
	if created, _ := s.RecordPending(ctx, "id1", "deploy", "fp1", `{}`, "r", "h"); created {
		t.Fatal("re-escalating a pending action must be idempotent")
	}
	if _, _, ok, _ := s.LookupApproved(ctx, "fp1"); ok {
		t.Fatal("pending is not approved")
	}
	if err := s.ApproveApproval(ctx, "id1", "tok", "lgtm"); err != nil {
		t.Fatal(err)
	}
	tok, id, ok, err := s.LookupApproved(ctx, "fp1")
	if err != nil || !ok || tok != "tok" || id != "id1" {
		t.Fatalf("lookup after approve: %q %q %v %v", tok, id, ok, err)
	}
	if err := s.Consume(ctx, "id1"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := s.LookupApproved(ctx, "fp1"); ok {
		t.Fatal("consumed release must not look up as approved (one-time)")
	}
	// A consumed row re-escalates as fresh pending.
	if created, _ := s.RecordPending(ctx, "id1", "deploy", "fp1", `{}`, "r", "h"); !created {
		t.Fatal("re-occurrence after consume needs a NEW approval")
	}
	if err := s.DenyApproval(ctx, "id1", "no"); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetApproval(ctx, "id1")
	if err != nil || a.Status != "denied" || a.Reason != "no" {
		t.Fatalf("deny: %v %+v", err, a)
	}
	if all, _ := s.ListApprovals(ctx, ""); len(all) != 1 {
		t.Fatalf("list: %+v", all)
	}
}

// The property the whole sequenced-tool design rests on, on the backend where it is least
// obviously true: many concurrent redeems of one grant, exactly one succeeds.
func TestPostgresRedeemIsAtomicUnderConcurrency(t *testing.T) {
	s := pgOpen(t)
	ctx := context.Background()
	g := proxy.Grant{Fingerprint: "fp", Tool: "t", Source: "policy:x", Session: "sess", Run: "run1"}
	if err := s.Mint(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := s.Mint(ctx, g); err != nil { // re-mint replaces, never stacks
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := s.Redeem(ctx, "fp", "sess"); err != nil {
				t.Error(err)
			} else if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("one-shot grant redeemed %d times", wins.Load())
	}
	// Wrong session never redeems, and Sweep is run-scoped.
	if err := s.Mint(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Redeem(ctx, "fp", "other-session"); ok {
		t.Fatal("another session spent a grant it does not own")
	}
	if err := s.Sweep(ctx, "sess", "run-other"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Redeem(ctx, "fp", "sess"); !ok {
		t.Fatal("sweep of a different run removed this run's grant")
	}
}

// The property A.3 exists for: replicas share one crossing counter. 32 racers, cap 5, exactly 5 win,
// on the backend the cluster will actually run.
func TestPostgresBindingAndAtomicCrossingBudget(t *testing.T) {
	s := pgOpen(t)
	ctx := context.Background()
	want := sampleBinding("pg-sess", 5)
	if err := s.PutBinding(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetBinding(ctx, "pg-sess")
	if err != nil || !ok {
		t.Fatalf("get: %v %v", ok, err)
	}
	got.CreatedAt = ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.ReserveCrossing(ctx, "pg-sess"); err != nil {
				t.Error(err)
			} else if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 5 {
		t.Fatalf("cap 5, %d reservations won on postgres", wins.Load())
	}
	if removed, _ := s.DeleteBinding(ctx, "pg-sess"); !removed {
		t.Fatal("revoke must remove")
	}
	if ok, _ := s.ReserveCrossing(ctx, "pg-sess"); ok {
		t.Fatal("revoked binding must not reserve")
	}
}

func TestPostgresSchemaGuardRefusesStaleTable(t *testing.T) {
	dsn := os.Getenv("STAG_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("STAG_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(pgTables); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE route (
		tool_name TEXT NOT NULL, server_name TEXT NOT NULL,
		recipe_name TEXT NOT NULL, gate_arg TEXT NOT NULL,
		PRIMARY KEY (tool_name, server_name))`); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dsn)
	if err == nil {
		_ = s.Close()
		t.Fatal("Open must refuse a route table that predates `sequenced` on postgres too")
	}
	if !contains(err.Error(), "sequenced") {
		t.Fatalf("error must name the missing column: %v", err)
	}
	_, _ = raw.Exec(pgTables)
}
