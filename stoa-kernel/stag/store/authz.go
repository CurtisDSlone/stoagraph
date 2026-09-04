package store

// file-kw: authorization grant ephemeral one-shot mint redeem restore sweep session atomic sequenced

import (
	"context"
	"database/sql"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// Mint records a one-shot authorization for exactly one call, owned by one session.
//
// Re-minting the same fingerprint REPLACES the row rather than stacking: a grant is permission
// for one call, not a counter. Two identical authorizations in flight would let a sequence spend
// one and leave the other outstanding.
// kw: mint grant one-shot replace not-stack session-owned
func (s *Store) Mint(ctx context.Context, g proxy.Grant) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authorization_grant (fingerprint, tool, source, session, run, created_at) VALUES (?,?,?,?,?,?)
		 ON CONFLICT(fingerprint) DO UPDATE SET tool=excluded.tool, source=excluded.source,
		   session=excluded.session, run=excluded.run, created_at=excluded.created_at`,
		g.Fingerprint, g.Tool, g.Source, g.Session, g.Run, nowRFC3339())
	return err
}

// Redeem claims a grant for `session` and returns it, ATOMICALLY: the DELETE both finds and
// removes the row, so two concurrent callers cannot both succeed. A check followed by a separate
// spend is a TOCTOU window wide enough to double-spend a one-shot authorization.
//
// The session predicate is part of the same statement. A grant belonging to another session is
// neither returned nor deleted — one agent's failed attempt must not consume another's
// authorization. An empty session matches only a grant that also has none, and Decide never
// redeems with an empty session for a session-bound gate.
// kw: redeem atomic delete-returning claim session-scoped no-toctou
func (s *Store) Redeem(ctx context.Context, fingerprint, session string) (proxy.Grant, bool, error) {
	var g proxy.Grant
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM authorization_grant WHERE fingerprint = ? AND session = ?
		 RETURNING fingerprint, tool, source, session, run`, fingerprint, session).
		Scan(&g.Fingerprint, &g.Tool, &g.Source, &g.Session, &g.Run)
	if err == sql.ErrNoRows {
		return proxy.Grant{}, false, nil
	}
	if err != nil {
		return proxy.Grant{}, false, err // an error is NOT a grant (fail closed)
	}
	return g, true, nil
}

// Restore puts back a claimed grant whose call did not happen after all — the gate refused it
// downstream of the claim, so the authorization is still owed.
// kw: restore grant refused call still-owed
func (s *Store) Restore(ctx context.Context, g proxy.Grant) error {
	return s.Mint(ctx, g)
}

// Sweep discards the outstanding grants of ONE RUN. A sequence that dies between minting and
// calling would otherwise leave a live authorization in the database, and a one-shot grant that
// survives its sequence is a standing one.
//
// Scoped to the run, not just the session: two sequences can share a session, and a
// session-wide sweep would delete a concurrent run's grant mid-flight and halt it for no
// policy reason.
// kw: sweep run-scoped grants abandoned expire no-standing-authorization concurrent-safe
func (s *Store) Sweep(ctx context.Context, session, run string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM authorization_grant WHERE session = ? AND run = ?`, session, run)
	return err
}
