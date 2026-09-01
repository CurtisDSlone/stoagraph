package gate

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

func TestSinkGate(t *testing.T) {
	tests := []struct {
		name     string
		subject  trust.TrustClass
		sink     SinkSensitivity
		released bool
		want     Verdict
	}{
		// benign: not release-gated
		{"benign untrusted", trust.Untrusted, SinkBenign, false, Allow},
		{"benign authoritative", trust.Authoritative, SinkBenign, false, Allow},
		{"benign untrusted released", trust.Untrusted, SinkBenign, true, Allow},
		// authoritative, not released
		{"auth authoritative", trust.Authoritative, SinkAuthoritative, false, Allow},
		{"auth caller denied", trust.Caller, SinkAuthoritative, false, Deny},
		{"auth untrusted denied", trust.Untrusted, SinkAuthoritative, false, Deny},
		// authoritative, released
		{"auth untrusted released", trust.Untrusted, SinkAuthoritative, true, Allow},
		{"auth caller released", trust.Caller, SinkAuthoritative, true, Allow},
		{"auth authoritative released", trust.Authoritative, SinkAuthoritative, true, Allow},
		// fail closed
		{"unknown label fails closed", trust.TrustClass(99), SinkAuthoritative, false, Deny},
		{"unregistered sink refused", trust.Untrusted, SinkSensitivity(99), false, Deny},
	}
	for _, tt := range tests {
		if got := GateSink(tt.subject, tt.sink, tt.released); got != tt.want {
			t.Errorf("%s: GateSink(%v, %v, %v) = %v, want %v", tt.name, tt.subject, tt.sink, tt.released, got, tt.want)
		}
	}

	// SinkSensitivity string round-trip and error cases.
	for _, s := range []SinkSensitivity{SinkBenign, SinkAuthoritative} {
		if got, err := ParseSinkSensitivity(s.String()); err != nil || got != s {
			t.Errorf("ParseSinkSensitivity(%q) = (%v, %v), want (%v, nil)", s.String(), got, err, s)
		}
	}
	if got, err := ParseSinkSensitivity("unknown"); err == nil {
		t.Errorf("ParseSinkSensitivity(\"unknown\") should return error")
	} else if got == SinkBenign || got == SinkAuthoritative {
		t.Errorf("ParseSinkSensitivity error returned in-set %v, want a fail-closed sentinel", got)
	}
	if _, err := ParseSinkSensitivity("bogus"); err == nil {
		t.Errorf("ParseSinkSensitivity(\"bogus\") should return error")
	}
}

func FuzzSinkGate(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{2, 1, 0})
	f.Add([]byte{0, 1, 1})
	f.Add([]byte{1, 1, 0})
	f.Add([]byte{0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 3 {
			return
		}
		subject := trust.TrustClass(data[0] % 4)
		sink := SinkSensitivity(data[1] % 3)
		released := data[2]&1 == 1

		v := GateSink(subject, sink, released)

		if v != Allow && v != Escalate && v != Deny {
			t.Fatalf("GateSink(%v,%v,%v) = %v, not a defined verdict", subject, sink, released, v)
		}

		// Full contract per input, so any branch mutation is caught (not only fail-open).
		switch {
		case sink == SinkBenign:
			if v != Allow {
				t.Errorf("benign sink: GateSink(%v,benign,%v) = %v, want Allow", subject, released, v)
			}
		case sink == SinkAuthoritative && released:
			if v != Allow {
				t.Errorf("released: GateSink(%v,auth,true) = %v, want Allow", subject, v)
			}
		case sink == SinkAuthoritative && !released:
			want := Deny // Caller, Untrusted, severed: deny unless released
			if subject == trust.Authoritative {
				want = Allow
			}
			if v != want {
				t.Errorf("auth sink: GateSink(%v,auth,false) = %v, want %v", subject, v, want)
			}
			if v == Allow && subject != trust.Authoritative {
				t.Errorf("FAIL-OPEN: GateSink(%v,auth,false)=Allow, want Authoritative", subject)
			}
		default:
			if v != Deny {
				t.Errorf("unregistered sink: GateSink(%v,%v,%v) = %v, want Deny", subject, sink, released, v)
			}
		}
	})
}
