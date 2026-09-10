package gate_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
)

var allVerdicts = []gate.Verdict{gate.Allow, gate.Escalate, gate.Deny}

func TestVerdict(t *testing.T) {
	// And table (the rollup is conjunctive: the most restrictive verdict wins).
	andCases := []struct{ a, b, want gate.Verdict }{
		{gate.Allow, gate.Deny, gate.Deny}, {gate.Allow, gate.Escalate, gate.Escalate}, {gate.Escalate, gate.Deny, gate.Deny},
		{gate.Allow, gate.Allow, gate.Allow}, {gate.Deny, gate.Deny, gate.Deny},
	}
	for _, c := range andCases {
		if got := gate.And(c.a, c.b); got != c.want {
			t.Errorf("And(%v,%v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}

	// Idempotence, identity/absorbing, commutativity over every pair.
	for _, a := range allVerdicts {
		if gate.And(a, a) != a {
			t.Errorf("idempotence failed for %v", a)
		}
		if gate.And(a, gate.Allow) != a || gate.And(a, gate.Deny) != gate.Deny {
			t.Errorf("And identity/absorbing failed for %v", a)
		}
		for _, b := range allVerdicts {
			if gate.And(a, b) != gate.And(b, a) {
				t.Errorf("commutativity failed for %v,%v", a, b)
			}
		}
	}

	// Associativity over every triple.
	for _, a := range allVerdicts {
		for _, b := range allVerdicts {
			for _, c := range allVerdicts {
				if gate.And(gate.And(a, b), c) != gate.And(a, gate.And(b, c)) {
					t.Errorf("And associativity failed for %v,%v,%v", a, b, c)
				}
			}
		}
	}

	// String round-trip; error cases fail closed to Deny.
	for _, v := range allVerdicts {
		if got, err := gate.ParseVerdict(v.String()); err != nil || got != v {
			t.Errorf("ParseVerdict(%q) = (%v,%v), want (%v,nil)", v.String(), got, err, v)
		}
	}
	for _, s := range []string{"unknown", "bogus", ""} {
		if got, err := gate.ParseVerdict(s); err == nil {
			t.Errorf("ParseVerdict(%q) should error", s)
		} else if got != gate.Deny {
			t.Errorf("ParseVerdict(%q) error = %v, want Deny (fail closed)", s, got)
		}
	}

	// Fold identity and multi-arg fold (== max over the args).
	if gate.AndAll() != gate.Allow {
		t.Errorf("empty fold identity failed")
	}
	foldCases := []struct {
		vs  []gate.Verdict
		and gate.Verdict
	}{
		{[]gate.Verdict{gate.Escalate}, gate.Escalate},
		{[]gate.Verdict{gate.Allow, gate.Escalate, gate.Deny}, gate.Deny},
		{[]gate.Verdict{gate.Allow, gate.Escalate}, gate.Escalate},
		{[]gate.Verdict{gate.Escalate, gate.Deny}, gate.Deny},
		{[]gate.Verdict{gate.Allow, gate.Allow}, gate.Allow},
	}
	for _, c := range foldCases {
		if got := gate.AndAll(c.vs...); got != c.and {
			t.Errorf("AndAll(%v) = %v, want %v", c.vs, got, c.and)
		}
	}
}

func FuzzVerdictRollup(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{})
	f.Add([]byte{2, 2, 2})

	f.Fuzz(func(t *testing.T, data []byte) {
		var vs []gate.Verdict
		max := gate.Allow
		for _, b := range data {
			v := gate.Verdict(b % 3)
			vs = append(vs, v)
			if v > max {
				max = v
			}
		}
		if len(data) == 0 {
			max = gate.Allow
		}

		// The conjunctive fold equals the most restrictive (max) verdict in the batch.
		if got := gate.AndAll(vs...); got != max {
			t.Errorf("AndAll(%v) = %v, want %v", vs, got, max)
		}
	})
}
