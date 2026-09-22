package store

// file-kw: session binding persist replicas token-digest recipe-snapshot crossing-budget atomic-reserve

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// PutBinding persists a session binding. Upsert by id so a re-bind of the same digest (which cannot
// happen with a fresh random token, but the store should not depend on that) replaces rather than
// errors. The budget counter is reset with it: a new binding is a new grant.
// kw: put binding upsert json snapshot
func (s *Store) PutBinding(ctx context.Context, b proxy.Binding) error {
	routes, err := json.Marshal(b.Routes)
	if err != nil {
		return err
	}
	providers, err := json.Marshal(b.Providers)
	if err != nil {
		return err
	}
	recipes, err := json.Marshal(b.Recipes)
	if err != nil {
		return err
	}
	created := b.CreatedAt
	if created == "" {
		created = nowRFC3339()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO session (id, routes_json, providers_json, recipes_json, budget_limit, budget_used, created_at)
		 VALUES (?,?,?,?,?,0,?)
		 ON CONFLICT(id) DO UPDATE SET routes_json=excluded.routes_json, providers_json=excluded.providers_json,
		   recipes_json=excluded.recipes_json, budget_limit=excluded.budget_limit, budget_used=0, created_at=excluded.created_at`,
		b.ID, string(routes), string(providers), string(recipes), b.Budget, created)
	if err != nil {
		return fmt.Errorf("store: put binding: %w", err)
	}
	return nil
}

// GetBinding loads a binding by its digest. ok=false when there is none (revoked, or never bound).
// kw: get binding by digest fail-closed
func (s *Store) GetBinding(ctx context.Context, id string) (proxy.Binding, bool, error) {
	var b proxy.Binding
	var routes, providers, recipes string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, routes_json, providers_json, recipes_json, budget_limit, created_at FROM session WHERE id=?`, id).
		Scan(&b.ID, &routes, &providers, &recipes, &b.Budget, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return proxy.Binding{}, false, nil
	}
	if err != nil {
		return proxy.Binding{}, false, fmt.Errorf("store: get binding: %w", err)
	}
	if err := json.Unmarshal([]byte(routes), &b.Routes); err != nil {
		return proxy.Binding{}, false, fmt.Errorf("store: binding %s routes: %w", id, err)
	}
	if err := json.Unmarshal([]byte(providers), &b.Providers); err != nil {
		return proxy.Binding{}, false, fmt.Errorf("store: binding %s providers: %w", id, err)
	}
	if err := json.Unmarshal([]byte(recipes), &b.Recipes); err != nil {
		return proxy.Binding{}, false, fmt.Errorf("store: binding %s recipes: %w", id, err)
	}
	return b, true, nil
}

// HasBinding is the per-request liveness check behind Gate.Live: does the row still exist. Cheaper
// than GetBinding (no JSON), and it runs on every MCP request, so it should be.
// kw: has binding live revoked per-request
func (s *Store) HasBinding(ctx context.Context, id string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM session WHERE id=?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: has binding: %w", err)
	}
	return true, nil
}

// DeleteBinding revokes: the row is gone, so every replica's next HasBinding says no and every
// ReserveCrossing says no. Reports whether a row was removed, so a caller can tell a revoke from a
// no-op ("already gone" and "never existed" look the same to an operator in an incident).
// kw: delete binding revoke reports-removed
func (s *Store) DeleteBinding(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE id=?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete binding: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CountBindings is for /health.
func (s *Store) CountBindings(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM session`).Scan(&n)
	return n, err
}

// ReserveCrossing takes one crossing iff the binding exists and is under its cap, in ONE statement.
// The predicate and the increment are the same UPDATE, so two replicas racing for the last crossing
// cannot both win: the database serializes the row. A limit <= 0 is unlimited and always succeeds
// (the count is still kept, as telemetry). A missing row affects no rows, which is "no": a revoked
// session crosses nothing.
// kw: reserve crossing atomic update-where replicas no-double-spend
func (s *Store) ReserveCrossing(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE session SET budget_used = budget_used + 1 WHERE id=? AND (budget_limit <= 0 OR budget_used < budget_limit)`, id)
	if err != nil {
		return false, fmt.Errorf("store: reserve crossing: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ReleaseCrossing returns a reservation for a call that did not forward. Floors at zero.
// kw: release crossing floor-zero
func (s *Store) ReleaseCrossing(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE session SET budget_used = budget_used - 1 WHERE id=? AND budget_used > 0`, id)
	if err != nil {
		return fmt.Errorf("store: release crossing: %w", err)
	}
	return nil
}
