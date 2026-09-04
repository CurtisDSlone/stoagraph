package provider

import (
	"os"
	"testing"
)

// HOW MUCH untrusted content may enter the model's context is a bound the GATE owns, not a
// per-source tuning knob. A provider registration cannot widen it.
//
// It is set low on purpose. A `read` step has already narrowed twice — the author named the
// provider and enumerated the allowed queries — so a large k is not more information, it is the
// rest of the corpus arriving because nobody chose.

func TestReadBoundsDefault(t *testing.T) {
	b := Bounds()
	if b.K != DefaultK {
		t.Errorf("default k: %d, want %d", b.K, DefaultK)
	}
	if b.MaxChars != DefaultMaxChars {
		t.Errorf("default max_chars: %d, want %d", b.MaxChars, DefaultMaxChars)
	}
}

func TestReadBoundsFromEnv(t *testing.T) {
	t.Setenv("STOA_READ_K", "5")
	t.Setenv("STOA_READ_MAX_CHARS", "8000")
	b := Bounds()
	if b.K != 5 || b.MaxChars != 8000 {
		t.Errorf("env override: %+v", b)
	}
}

// FAIL SAFE. A garbage or out-of-range value falls back to the DEFAULT, never to "unbounded":
// a typo must not silently remove the bound on how much untrusted text reaches the model.
func TestReadBoundsFailSafe(t *testing.T) {
	cases := []struct{ name, k, mc string }{
		{"garbage k", "lots", ""},
		{"zero k", "0", ""},
		{"negative k", "-1", ""},
		{"k over the ceiling", "9999", ""},
		{"garbage max_chars", "", "loads"},
		{"zero max_chars", "", "0"},
		{"max_chars over the ceiling", "", "99999999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			os.Unsetenv("STOA_READ_K")
			os.Unsetenv("STOA_READ_MAX_CHARS")
			if c.k != "" {
				t.Setenv("STOA_READ_K", c.k)
			}
			if c.mc != "" {
				t.Setenv("STOA_READ_MAX_CHARS", c.mc)
			}
			b := Bounds()
			if b.K != DefaultK || b.MaxChars != DefaultMaxChars {
				t.Errorf("%s: must fall back to the defaults, got %+v", c.name, b)
			}
		})
	}
}

// The ceiling is reachable, so an operator who genuinely needs more can have it — up to a point
// the gate sets, not the configuration.
func TestReadBoundsCeilingIsInclusive(t *testing.T) {
	t.Setenv("STOA_READ_K", itoa(MaxK))
	t.Setenv("STOA_READ_MAX_CHARS", itoa(MaxMaxChars))
	b := Bounds()
	if b.K != MaxK || b.MaxChars != MaxMaxChars {
		t.Errorf("ceiling must be reachable: %+v", b)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
