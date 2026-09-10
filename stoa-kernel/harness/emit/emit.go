// Package emit detects and handles recipe-emitted events (lifecycle.emit.* sinks).
//
// When a recipe executes and sinks to a field prefixed with `lifecycle.emit.*`,
// the recipe has emitted an event. This package detects those sinks from EvalResult
// and creates new events for re-routing through the harness dispatcher.
//
// Pattern:
//
//	Recipe sinks to: lifecycle.emit.code_fix_required (with JSON payload in slot)
//	Harness detects: SinkOutcome with Field = "lifecycle.emit.code_fix_required"
//	Harness creates: Event{Source: "orchestration", Type: "code_fix_required", Payload: ...}
//	Harness routes: Through event_map like any other event
package emit

// file-kw: emit lifecycle-sink detect re-route event bounded-text cross-hop

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// How much attacker-influenceable text one emit may carry across a recipe hop.
//
// This is the ACT-side twin of provider.Bounds() (stag/provider/bounds.go), and it exists
// for the same reason: "how much attacker-influenced text reaches the model" is a security
// property, not configuration. A recipe cannot widen it — the bound belongs to the harness,
// not to the policy that emitted.
//
// An emit payload is a slot value, and a slot value can trace back to untrusted input (a PR
// body, an issue, a scanned file). It becomes the NEXT agent's event verbatim. Without a
// bound it also COMPOUNDS: each recipe in a chain may copy its inbound payload forward and
// add to it, so an unbounded hop is an unbounded chain.
//
// The default is generous relative to the READ channel (4000 chars) because an emit payload
// is structured hand-off, not retrieved prose — findings lists, statuses, ids. It is still a
// bound, and exceeding it FAILS the emit rather than truncating: a half-payload is a payload
// whose qualifier may have been cut off, and the next recipe cannot tell.
const (
	DefaultMaxPayloadBytes = 16000
	MaxMaxPayloadBytes     = 262144
)

// MaxPayloadBytes resolves the emit payload cap. STOA_EMIT_MAX_PAYLOAD overrides the default;
// anything unparseable or out of range falls back to the DEFAULT, never to unbounded — a typo
// must not silently remove a bound.
// kw: emit payload bound gate-owned env fail-safe never-unbounded
func MaxPayloadBytes() int {
	raw := os.Getenv("STOA_EMIT_MAX_PAYLOAD")
	if raw == "" {
		return DefaultMaxPayloadBytes
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxMaxPayloadBytes {
		return DefaultMaxPayloadBytes
	}
	return n
}

// Emit represents a detected emit sink with its value (from the slot).
type Emit struct {
	SinkOutcome stag.SinkOutcome
	SlotValue   string // the value from the slot being sunk
}

// EmittedEvent is an internal event created from a recipe's emit sink.
type EmittedEvent struct {
	ID         string          // unique identifier for this emitted event
	Source     string          // always "orchestration"
	Type       string          // extracted from lifecycle.emit.<type>
	Payload    json.RawMessage // the slot value (context for next recipe)
	Attributed bool            // always true (came from gated recipe evaluation)
	AuthMethod string          // "recipe_eval"
}

// DetectEmits examines an EvalResult and returns any emit sinks found.
// An emit sink is one with Field prefixed with "lifecycle.emit.".
// Note: caller must supply the corresponding slot values.
func DetectEmits(result stag.EvalResult) []stag.SinkOutcome {
	var emits []stag.SinkOutcome
	for _, sink := range result.Sinks {
		if strings.HasPrefix(sink.Field, "lifecycle.emit.") {
			emits = append(emits, sink)
		}
	}
	return emits
}

// ValidateEmit checks whether an emit sink satisfies constraints.
// Constraints:
//   - Field must start with "lifecycle.emit."
//   - Event kind (part after prefix) must be valid identifier
//   - Verdict must be Allow (emit sinks are benign, never breach)
//   - Payload should be valid JSON (for context reading)
func ValidateEmit(emit Emit) error {
	sink := emit.SinkOutcome

	// 1. Field must have the marker
	if !strings.HasPrefix(sink.Field, "lifecycle.emit.") {
		return fmt.Errorf("emit field %q must start with lifecycle.emit.", sink.Field)
	}

	// 2. Extract and validate kind
	kind := strings.TrimPrefix(sink.Field, "lifecycle.emit.")
	if kind == "" {
		return fmt.Errorf("emit field %q has empty kind after prefix", sink.Field)
	}
	if !IsValidEventKind(kind) {
		return fmt.Errorf("emit field %q: kind %q is not a valid identifier", sink.Field, kind)
	}

	// 3. Verdict must be Allow (benign sinks don't block)
	if sink.Verdict != stag.Allow {
		return fmt.Errorf("emit sink has verdict %v; must be Allow", sink.Verdict)
	}

	// 4. Payload size is BOUNDED. Fails the emit rather than truncating: a truncated payload
	// is one whose qualifier may have been cut off, and the next recipe cannot tell that it
	// was. Refusing to emit is the honest outcome — the chain stops and the audit says why.
	if n := len(emit.SlotValue); n > MaxPayloadBytes() {
		return fmt.Errorf("emit payload is %d bytes; exceeds the %d-byte bound", n, MaxPayloadBytes())
	}

	return nil
}

// IsValidEventKind reports whether a string is a valid event kind
// (lowercase letters, digits, underscores; start with letter).
func IsValidEventKind(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// NewEmittedEvent creates an event from an emit, ready for dispatch.
// The event source is always "orchestration" (indicates it came from a recipe).
// The event type is extracted from the emit's field name.
// The event payload is the slot value (context for next recipe).
func NewEmittedEvent(sourceEventID string, emit Emit, generationNum int) EmittedEvent {
	kind := strings.TrimPrefix(emit.SinkOutcome.Field, "lifecycle.emit.")
	return EmittedEvent{
		ID:         fmt.Sprintf("%s__emit_%d", sourceEventID, generationNum),
		Source:     "orchestration",
		Type:       kind,
		Payload:    []byte(emit.SlotValue),
		Attributed: true,
		AuthMethod: "recipe_eval",
	}
}

// TrustKey is the dispatch-event key carrying an emit payload's origin trust class.
// The harness reads it to decide HOW to frame the payload for the next agent.
const TrustKey = "_trust"

// ToDispatchEvent converts an EmittedEvent to a dispatch.Event (for re-routing).
// This is the bridge between the emit detection and the dispatcher.
//
// The event is STAMPED UNTRUSTED. An emit payload is a slot value, and a slot value can
// trace back to untrusted input (a PR body, an issue, a scanned file) that the recipe merely
// copied. Without the stamp, copied text and recipe-authored text are indistinguishable to
// both the next agent and the audit — the emitted event would claim recipe provenance for
// bytes an attacker wrote.
//
// This mirrors provider.Gather stamping every READ item untrusted at origin. The stamp is
// unconditional for the same reason it is there: a marker applied only when someone judged
// the content suspicious is a marker that is missing exactly when it matters.
func (e EmittedEvent) ToDispatchEvent() map[string]any {
	m := map[string]any{
		"source": e.Source,
		"kind":   e.Type,
		TrustKey: stag.Untrusted.String(),
	}

	// Include payload as part of the event if it's valid JSON
	if len(strings.TrimSpace(string(e.Payload))) > 0 {
		var payload any
		if json.Unmarshal(e.Payload, &payload) == nil {
			m["payload"] = payload
		} else {
			// Fall back to raw string if not JSON
			m["payload"] = string(e.Payload)
		}
	}

	return m
}
