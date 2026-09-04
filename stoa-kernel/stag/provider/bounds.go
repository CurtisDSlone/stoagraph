package provider

// file-kw: read bounds k max-chars gate-owned env override fail-safe untrusted-context-volume

import (
	"os"
	"strconv"
)

// How much untrusted content a single read may put into the model's context. This is a bound the
// GATE owns, not a per-source tuning knob: a provider registration cannot widen it, because "how
// much attacker-influenced text reaches the model" is a security property and not configuration.
//
// The defaults are LOW on purpose. A `read` step has already narrowed twice — the author named
// the provider and enumerated the queries its rule permits — so a large k is not more relevant
// information, it is the rest of the corpus arriving because nobody chose. Measured on a 15-file
// runbook library: the query "drain" matches 13 files and 10,697 characters. Two documents is a
// briefing; thirteen is the corpus.
//
// Both bounds are needed and they fail differently: k caps HOW MANY documents, max_chars caps HOW
// MUCH TEXT. Ten one-line documents and one enormous document are different problems.
const (
	DefaultK        = 2
	DefaultMaxChars = 4000

	// Ceilings an operator cannot exceed. An out-of-range value falls back to the DEFAULT rather
	// than clamping to the ceiling — asking for 9999 is a mistake, and quietly giving someone the
	// maximum is not what they asked for either.
	MaxK        = 10
	MaxMaxChars = 32000
)

// ReadBounds is the resolved per-read limit.
// kw: read bounds resolved k max chars
type ReadBounds struct {
	K        int
	MaxChars int
}

// Bounds resolves the gate-wide read limits: STOA_READ_K and STOA_READ_MAX_CHARS override the
// defaults, and anything unparseable or out of range falls back to the default — never to
// unbounded. A typo must not silently remove a bound.
// kw: bounds env override fail-safe never-unbounded
func Bounds() ReadBounds {
	return ReadBounds{
		K:        envInt("STOA_READ_K", DefaultK, MaxK),
		MaxChars: envInt("STOA_READ_MAX_CHARS", DefaultMaxChars, MaxMaxChars),
	}
}

// kw: env int bounded fallback
func envInt(key string, def, max int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return def // fail safe: garbage or out of range means the default, not "no limit"
	}
	return n
}

// Apply trims a result set to the bounds: at most K items, and at most MaxChars of text across
// them. Truncation is by WHOLE ITEMS — a half-document is worse than one fewer document, because
// the model cannot tell it was cut and may act on an instruction that lost its qualifier.
//
// The first item is always kept even if it alone exceeds MaxChars: returning nothing when the
// single best match is large would be a silent empty read, and an empty read is a claim that
// there was no context.
// kw: apply bounds trim whole-items never-half-a-document keep-first
func (b ReadBounds) Apply(items []ContextItem) []ContextItem {
	out := make([]ContextItem, 0, len(items))
	total := 0
	for i, it := range items {
		if i >= b.K {
			break
		}
		if i > 0 && total+len(it.Text) > b.MaxChars {
			break
		}
		out = append(out, it)
		total += len(it.Text)
	}
	return out
}
