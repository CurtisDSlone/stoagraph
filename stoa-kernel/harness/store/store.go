// Package store is the event_harness's own model-provider config: which models the
// orchestrator can drive, and where their keys live. This is the config that was removed
// from stag (the gate holds no keys) — it belongs HERE, on the orchestrator side.
// A JSON file, not SQLite: the orchestrator's config is small and human-editable.
package store

// file-kw: orchestrator store models api-keys json file key-env never-echoed keys-live-here

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Model is a connected model provider. A key is supplied directly (APIKey, dev) or by
// naming an env var (APIKeyEnv); APIKey wins. The API never echoes a stored key.
type Model struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // "claude" | "openai"
	BaseURL   string `json:"baseUrl"`
	Model     string `json:"model"`
	APIKey    string `json:"apiKey,omitempty"`
	APIKeyEnv string `json:"apiKeyEnv,omitempty"`
	// TimeoutSeconds is how long to wait for THIS model to answer. A model behind a gateway —
	// a queue, a proxy, an inference server under load — can legitimately take minutes, and a
	// hardcoded limit made such an endpoint unusable rather than slow.
	//
	// It lives on the model, not the process: one deployment may reach a fast endpoint and a
	// slow one at once, and a single global value would have to be the maximum of the two.
	// 0 means unset (use the default), never "unlimited".
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// Request-timeout bounds. Unbounded is NOT offered: a hung request would pin a dispatch with no
// other way to end, and "wait forever" is not a timeout policy. An out-of-range or unparseable
// value falls back to the default rather than to no limit — a config typo must not silently
// remove a bound.
const (
	DefaultRequestTimeout = 90 * time.Second
	MaxRequestTimeout     = 15 * time.Minute
)

// RequestTimeout resolves how long to wait for this model, in precedence order:
//
//	STOA_MODEL_TIMEOUT_SECONDS_<NAME>   per-model env override
//	STOA_MODEL_TIMEOUT_SECONDS          global env override
//	timeoutSeconds in models.json       the configured value
//	DefaultRequestTimeout
//
// The env layer exists so an operator can raise a limit for one run without editing config —
// the same escape hatch apiKeyEnv gives for secrets.
// kw: model request timeout config env override bounded fail-safe gateway latency
func (m Model) RequestTimeout() time.Duration {
	if v, ok := timeoutFromEnv("STOA_MODEL_TIMEOUT_SECONDS_" + envToken(m.Name)); ok {
		return v
	}
	if v, ok := timeoutFromEnv("STOA_MODEL_TIMEOUT_SECONDS"); ok {
		return v
	}
	if d, ok := validTimeout(m.TimeoutSeconds); ok {
		return d
	}
	return DefaultRequestTimeout
}

// kw: timeout env parse bounded
func timeoutFromEnv(key string) (time.Duration, bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false // garbage falls through to the next layer, never to "no limit"
	}
	return validTimeout(n)
}

// kw: timeout range check inclusive ceiling
func validTimeout(seconds int) (time.Duration, bool) {
	if seconds < 1 {
		return 0, false // 0 is UNSET, not unlimited
	}
	d := time.Duration(seconds) * time.Second
	if d > MaxRequestTimeout {
		return 0, false
	}
	return d, true
}

// envToken maps a model name onto the env-var alphabet, so a hyphenated name like "gpt-4o" is
// reachable as ..._GPT_4O rather than silently unmatchable.
// kw: env token normalize model name uppercase
func envToken(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Key resolves the usable secret: stored directly, else the named env var.
func (m Model) Key() string {
	if m.APIKey != "" {
		return m.APIKey
	}
	if m.APIKeyEnv != "" {
		return os.Getenv(m.APIKeyEnv)
	}
	return ""
}

// Store is a JSON-file-backed set of models, keyed by name.
type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) *Store { return &Store{path: path} }

func (s *Store) load() ([]Model, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ms []Model
	if len(b) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &ms); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return ms, nil
}

func (s *Store) save(ms []Model) error {
	sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
	b, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600) // 0600: it may hold keys
}

func (s *Store) List() ([]Model, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) Get(name string) (Model, bool, error) {
	ms, err := s.List()
	if err != nil {
		return Model{}, false, err
	}
	for _, m := range ms {
		if m.Name == name {
			return m, true, nil
		}
	}
	return Model{}, false, nil
}

// Put upserts by name. An empty APIKey preserves the existing stored key (edit without
// re-entering it).
func (s *Store) Put(m Model) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return err
	}
	replaced := false
	for i := range ms {
		if ms[i].Name == m.Name {
			if m.APIKey == "" {
				m.APIKey = ms[i].APIKey // preserve
			}
			ms[i] = m
			replaced = true
			break
		}
	}
	if !replaced {
		ms = append(ms, m)
	}
	return s.save(ms)
}

func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return err
	}
	out := ms[:0]
	for _, m := range ms {
		if m.Name != name {
			out = append(out, m)
		}
	}
	return s.save(out)
}
