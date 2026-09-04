package store

import (
	"os"
	"testing"
	"time"
)

// A model behind a gateway can be slow — a queue, a proxy, an inference server under load — and
// the client's timeout is what decides whether "slow" means "failed". It was a hardcoded 90s in
// the agent loop with no way to change it, so a gated endpoint that took longer could not be
// used at all.
//
// It belongs on the MODEL, not on the process: one deployment may reach a fast endpoint and a
// slow one at once, and a single global value would have to be the max of the two.

func TestTimeoutDefaultsWhenUnset(t *testing.T) {
	m := Model{Name: "x", Kind: "openai"}
	if got := m.RequestTimeout(); got != DefaultRequestTimeout {
		t.Errorf("an unset timeout must default: %v, want %v", got, DefaultRequestTimeout)
	}
}

func TestTimeoutFromConfig(t *testing.T) {
	m := Model{Name: "x", Kind: "openai", TimeoutSeconds: 240}
	if got := m.RequestTimeout(); got != 240*time.Second {
		t.Errorf("configured timeout: %v", got)
	}
}

// The env var overrides the file, so an operator can raise it for one run without editing
// config — the same escape hatch apiKeyEnv gives for secrets.
func TestTimeoutEnvOverridesConfig(t *testing.T) {
	t.Setenv("STOA_MODEL_TIMEOUT_SECONDS", "300")
	m := Model{Name: "x", Kind: "openai", TimeoutSeconds: 60}
	if got := m.RequestTimeout(); got != 300*time.Second {
		t.Errorf("env must win over the file: %v", got)
	}
}

// A per-model env var beats the global one: a deployment with one slow endpoint and one fast one
// must be able to raise just the slow one.
func TestPerModelEnvBeatsGlobalEnv(t *testing.T) {
	t.Setenv("STOA_MODEL_TIMEOUT_SECONDS", "300")
	t.Setenv("STOA_MODEL_TIMEOUT_SECONDS_SLOWONE", "600")
	fast := Model{Name: "fast", Kind: "openai"}
	slow := Model{Name: "slowone", Kind: "openai"}
	if got := fast.RequestTimeout(); got != 300*time.Second {
		t.Errorf("fast model takes the global env: %v", got)
	}
	if got := slow.RequestTimeout(); got != 600*time.Second {
		t.Errorf("slow model takes its own env: %v", got)
	}
}

// A model name is not necessarily an env-var-safe token. The lookup must normalize rather than
// silently miss: "gpt-4o" would otherwise be unreachable by env.
func TestPerModelEnvNormalizesTheName(t *testing.T) {
	t.Setenv("STOA_MODEL_TIMEOUT_SECONDS_GPT_4O", "450")
	m := Model{Name: "gpt-4o", Kind: "openai"}
	if got := m.RequestTimeout(); got != 450*time.Second {
		t.Errorf("a hyphenated model name must map to an env var: %v", got)
	}
}

// FAIL SAFE, not fail open. A garbage or out-of-range value falls back to the default rather
// than to "no timeout": an unbounded request would pin a dispatch forever with no other way to
// end, and a config typo must not silently remove a bound.
func TestOutOfRangeAndGarbageFallBackToTheDefault(t *testing.T) {
	cases := []struct {
		name string
		cfg  int
		env  string
	}{
		{"negative", -1, ""},
		{"zero is unset, not unlimited", 0, ""},
		{"over the ceiling", int(MaxRequestTimeout/time.Second) + 1, ""},
		{"garbage env", 0, "not-a-number"},
		{"negative env", 0, "-5"},
		{"over-ceiling env", 0, "999999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.env != "" {
				t.Setenv("STOA_MODEL_TIMEOUT_SECONDS", c.env)
			} else {
				os.Unsetenv("STOA_MODEL_TIMEOUT_SECONDS")
			}
			m := Model{Name: "x", Kind: "openai", TimeoutSeconds: c.cfg}
			if got := m.RequestTimeout(); got != DefaultRequestTimeout {
				t.Errorf("%s: must fall back to the default, got %v", c.name, got)
			}
		})
	}
}

// The ceiling itself is usable: a value exactly at the limit is accepted.
func TestCeilingIsInclusive(t *testing.T) {
	m := Model{Name: "x", Kind: "openai", TimeoutSeconds: int(MaxRequestTimeout / time.Second)}
	if got := m.RequestTimeout(); got != MaxRequestTimeout {
		t.Errorf("the ceiling must be reachable: %v", got)
	}
}
