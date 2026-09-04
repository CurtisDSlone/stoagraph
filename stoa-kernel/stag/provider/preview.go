package provider

// file-kw: preview enumerate read queries finite set what-context-will-arrive reviewable

import (
	"context"
	"sort"
)

// PreviewRow is what one permitted query actually returns.
// kw: preview row query sources chars empty
type PreviewRow struct {
	Query   string   `json:"query"`
	Sources []string `json:"sources"`
	Chars   int      `json:"chars"`
	Matched int      `json:"matched"` // before the read bounds were applied
	Empty   bool     `json:"empty"`   // the query is permitted and retrieves NOTHING
}

// Preview enumerates what a `read` step will actually fetch, for every query its rule permits.
//
// This is possible because a read is FINITE by construction: the author named one provider and
// the query rule is a closed set of literal values, so the whole space of possible retrievals is
// (one source) x (N known queries) — small, and knowable before the recipe ever runs. Generic
// retrieval cannot be previewed this way, because its query is whatever the model writes.
//
// It exists for the failure the audit cannot show you afterwards: a query the author PERMITTED
// that retrieves nothing. The policy promises context and silently delivers none, and nothing at
// runtime distinguishes that from a source that simply had no answer.
// kw: preview enumerate finite closed-set reviewable empty-retrieval
func Preview(ctx context.Context, p ContextProvider, queries []string) []PreviewRow {
	b := Bounds()
	rows := make([]PreviewRow, 0, len(queries))
	seen := map[string]bool{}
	for _, q := range queries {
		if seen[q] {
			continue
		}
		seen[q] = true

		bounded, _ := BoundQuery(q)
		items, err := p.Provide(ctx, bounded)
		if err != nil {
			rows = append(rows, PreviewRow{Query: q, Empty: true})
			continue
		}
		matched := len(items)
		for i := range items {
			items[i].Trust = Untrusted
		}
		items = b.Apply(items)

		row := PreviewRow{Query: q, Matched: matched, Empty: len(items) == 0}
		for _, it := range items {
			row.Sources = append(row.Sources, it.Source)
			row.Chars += len(it.Text)
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Query < rows[j].Query })
	return rows
}
