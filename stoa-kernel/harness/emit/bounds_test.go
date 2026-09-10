package emit_test

import (
	"os"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

func allowSink(field string) stag.SinkOutcome {
	return stag.SinkOutcome{Field: field, Verdict: stag.Allow}
}

func TestPayloadBoundRejectsOversize(t *testing.T) {
	e := emit.Emit{
		SinkOutcome: allowSink("lifecycle.emit.code_fix_required"),
		SlotValue:   strings.Repeat("A", emit.DefaultMaxPayloadBytes+1),
	}
	err := emit.ValidateEmit(e)
	if err == nil {
		t.Fatal("oversize payload was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should name the bound: %v", err)
	}
}

func TestPayloadBoundAcceptsAtLimit(t *testing.T) {
	e := emit.Emit{
		SinkOutcome: allowSink("lifecycle.emit.code_fix_required"),
		SlotValue:   strings.Repeat("A", emit.DefaultMaxPayloadBytes),
	}
	if err := emit.ValidateEmit(e); err != nil {
		t.Fatalf("payload exactly at the bound was rejected: %v", err)
	}
}

// The bound fails SAFE: garbage or out-of-range env falls back to the default,
// never to unbounded. Mirrors provider.envInt.
func TestPayloadBoundEnvFailsSafe(t *testing.T) {
	for _, v := range []string{"not-a-number", "0", "-5", "99999999"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("STOA_EMIT_MAX_PAYLOAD", v)
			if got := emit.MaxPayloadBytes(); got != emit.DefaultMaxPayloadBytes {
				t.Errorf("STOA_EMIT_MAX_PAYLOAD=%q gave %d, want default %d", v, got, emit.DefaultMaxPayloadBytes)
			}
		})
	}
}

func TestPayloadBoundEnvOverrides(t *testing.T) {
	t.Setenv("STOA_EMIT_MAX_PAYLOAD", "100")
	if got := emit.MaxPayloadBytes(); got != 100 {
		t.Fatalf("MaxPayloadBytes() = %d, want 100", got)
	}
	e := emit.Emit{SinkOutcome: allowSink("lifecycle.emit.x"), SlotValue: strings.Repeat("A", 101)}
	if err := emit.ValidateEmit(e); err == nil {
		t.Error("payload over the overridden bound was accepted")
	}
}

// A recipe cannot widen the bound: it is resolved from the harness environment,
// never from anything the emitting recipe supplies.
func TestPayloadBoundIsNotRecipeControlled(t *testing.T) {
	os.Unsetenv("STOA_EMIT_MAX_PAYLOAD")
	if emit.MaxPayloadBytes() != emit.DefaultMaxPayloadBytes {
		t.Fatal("unset env should yield the default")
	}
	// The Emit struct carries no bound field — a recipe has no channel to raise it.
	e := emit.Emit{SinkOutcome: allowSink("lifecycle.emit.x"), SlotValue: strings.Repeat("A", emit.DefaultMaxPayloadBytes+1)}
	if err := emit.ValidateEmit(e); err == nil {
		t.Error("recipe-supplied oversize payload was accepted")
	}
}

func TestDispatchEventIsStampedUntrusted(t *testing.T) {
	e := emit.Emit{
		SinkOutcome: allowSink("lifecycle.emit.code_fix_required"),
		SlotValue:   `{"findings":["sql_injection"]}`,
	}
	d := emit.NewEmittedEvent("evt_001", e, 1).ToDispatchEvent()

	stamp, ok := d[emit.TrustKey].(string)
	if !ok {
		t.Fatalf("dispatch event has no %s key: %#v", emit.TrustKey, d)
	}
	if stamp != stag.Untrusted.String() {
		t.Errorf("%s = %q, want %q", emit.TrustKey, stamp, stag.Untrusted.String())
	}
}

// The stamp is UNCONDITIONAL — it does not depend on payload shape or content.
// A marker applied only to content someone judged suspicious is missing exactly
// when it matters.
func TestStampIsUnconditional(t *testing.T) {
	for _, payload := range []string{`{"a":1}`, "", "not json at all", `"plain string"`} {
		t.Run(payload, func(t *testing.T) {
			e := emit.Emit{SinkOutcome: allowSink("lifecycle.emit.x"), SlotValue: payload}
			d := emit.NewEmittedEvent("evt_001", e, 1).ToDispatchEvent()
			if d[emit.TrustKey] != stag.Untrusted.String() {
				t.Errorf("payload %q lost its stamp: %#v", payload, d)
			}
		})
	}
}
