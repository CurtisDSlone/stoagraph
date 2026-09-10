package trust_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

func TestTrustClass(t *testing.T) {
	// Ordering is Untrusted < Caller < Authoritative — the sink gate compares against it.
	if !(trust.Untrusted < trust.Caller && trust.Caller < trust.Authoritative) {
		t.Fatalf("trust class ordering broken: %d %d %d", trust.Untrusted, trust.Caller, trust.Authoritative)
	}

	// String <-> ParseTrustClass round-trip.
	for _, c := range []trust.TrustClass{trust.Untrusted, trust.Caller, trust.Authoritative} {
		s := c.String()
		parsed, err := trust.ParseTrustClass(s)
		if err != nil {
			t.Errorf("ParseTrustClass(%q) returned error: %v", s, err)
		}
		if parsed != c {
			t.Errorf("ParseTrustClass(%q) = %v, want %v", s, parsed, c)
		}
	}

	// Unknown strings fail with an error (fail closed at the parse boundary).
	for _, s := range []string{"bogus", "unknown", "untrustedx", "callerx", "authoritativex", ""} {
		if _, err := trust.ParseTrustClass(s); err == nil {
			t.Errorf("ParseTrustClass(%q) should have returned error", s)
		}
	}
}
