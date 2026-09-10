package gate_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

func TestSinkGate(t *testing.T) {
	tests := []struct {
		name     string
		subject  trust.TrustClass
		sink     gate.SinkSensitivity
		released bool
		want     gate.Verdict
	}{
		// benign: not release-gated
		{"benign untrusted", trust.Untrusted, gate.SinkBenign, false, gate.Allow},
		{"benign authoritative", trust.Authoritative, gate.SinkBenign, false, gate.Allow},
		{"benign untrusted released", trust.Untrusted, gate.SinkBenign, true, gate.Allow},
		// authoritative, not released
		{"auth authoritative", trust.Authoritative, gate.SinkAuthoritative, false, gate.Allow},
		{"auth caller denied", trust.Caller, gate.SinkAuthoritative, false, gate.Deny},
		{"auth untrusted denied", trust.Untrusted, gate.SinkAuthoritative, false, gate.Deny},
		// authoritative, released
		{"auth untrusted released", trust.Untrusted, gate.SinkAuthoritative, true, gate.Allow},
		{"auth caller released", trust.Caller, gate.SinkAuthoritative, true, gate.Allow},
		{"auth authoritative released", trust.Authoritative, gate.SinkAuthoritative, true, gate.Allow},
		// fail closed
		{"unknown label fails closed", trust.TrustClass(99), gate.SinkAuthoritative, false, gate.Deny},
		{"unregistered sink refused", trust.Untrusted, gate.SinkSensitivity(99), false, gate.Deny},
	}
	for _, tt := range tests {
		if got := gate.GateSink(tt.subject, tt.sink, tt.released); got != tt.want {
			t.Errorf("%s: GateSink(%v, %v, %v) = %v, want %v", tt.name, tt.subject, tt.sink, tt.released, got, tt.want)
		}
	}

	// SinkSensitivity string round-trip and error cases.
	for _, s := range []gate.SinkSensitivity{gate.SinkBenign, gate.SinkAuthoritative} {
		if got, err := gate.ParseSinkSensitivity(s.String()); err != nil || got != s {
			t.Errorf("ParseSinkSensitivity(%q) = (%v, %v), want (%v, nil)", s.String(), got, err, s)
		}
	}
	if got, err := gate.ParseSinkSensitivity("unknown"); err == nil {
		t.Errorf("ParseSinkSensitivity(\"unknown\") should return error")
	} else if got == gate.SinkBenign || got == gate.SinkAuthoritative {
		t.Errorf("ParseSinkSensitivity error returned in-set %v, want a fail-closed sentinel", got)
	}
	if _, err := gate.ParseSinkSensitivity("bogus"); err == nil {
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
		sink := gate.SinkSensitivity(data[1] % 3)
		released := data[2]&1 == 1

		v := gate.GateSink(subject, sink, released)

		if v != gate.Allow && v != gate.Escalate && v != gate.Deny {
			t.Fatalf("GateSink(%v,%v,%v) = %v, not a defined verdict", subject, sink, released, v)
		}

		// Full contract per input, so any branch mutation is caught (not only fail-open).
		switch {
		case sink == gate.SinkBenign:
			if v != gate.Allow {
				t.Errorf("benign sink: GateSink(%v,benign,%v) = %v, want Allow", subject, released, v)
			}
		case sink == gate.SinkAuthoritative && released:
			if v != gate.Allow {
				t.Errorf("released: GateSink(%v,auth,true) = %v, want Allow", subject, v)
			}
		case sink == gate.SinkAuthoritative && !released:
			want := gate.Deny // Caller, Untrusted, severed: deny unless released
			if subject == trust.Authoritative {
				want = gate.Allow
			}
			if v != want {
				t.Errorf("auth sink: GateSink(%v,auth,false) = %v, want %v", subject, v, want)
			}
			if v == gate.Allow && subject != trust.Authoritative {
				t.Errorf("FAIL-OPEN: GateSink(%v,auth,false)=Allow, want Authoritative", subject)
			}
		default:
			if v != gate.Deny {
				t.Errorf("unregistered sink: GateSink(%v,%v,%v) = %v, want Deny", subject, sink, released, v)
			}
		}
	})
}
