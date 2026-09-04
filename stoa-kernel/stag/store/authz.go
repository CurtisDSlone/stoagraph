package store

// file-kw: authorization grant ephemeral one-shot mint lookup burn sequenced route provenance

import (
	"context"
	"database/sql"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// Mint records a one-shot authorization for exactly one call.
//
// Re-minting the same fingerprint REPLACES the row rather than stacking: a grant is a permission
// for one call, not a counter. Two identical authorizations in flight would otherwise let a
// sequence spend one and leave the other outstanding.
// kw: mint grant one-shot replace not-stack
func (s *Store) Mint(ctx context.Context, g proxy.Grant) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authorization_grant (fingerprint, tool, source, created_at) VALUES (?,?,?,?)
		 ON CONFLICT(fingerprint) DO UPDATE SET tool=excluded.tool, source=excluded.source, created_at=excluded.created_at`,
		g.Fingerprint, g.Tool, g.Source, nowRFC3339())
	return err
}

// Lookup returns the outstanding grant for a fingerprint, if any.
// kw: lookup grant live outstanding
func (s *Store) Lookup(ctx context.Context, fingerprint string) (proxy.Grant, bool, error) {
	var g proxy.Grant
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint, tool, source FROM authorization_grant WHERE fingerprint = ?`, fingerprint).
		Scan(&g.Fingerprint, &g.Tool, &g.Source)
	if err == sql.ErrNoRows {
		return proxy.Grant{}, false, nil
	}
	if err != nil {
		return proxy.Grant{}, false, err // an error is NOT a grant (fail closed)
	}
	return g, true, nil
}

// Burn spends a grant. A replay then finds nothing and is denied.
// kw: burn grant spend one-time replay-denied
func (s *Store) Burn(ctx context.Context, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM authorization_grant WHERE fingerprint = ?`, fingerprint)
	return err
}
