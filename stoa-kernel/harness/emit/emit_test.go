package emit_test

import (
	"strings"
	"testing"

	pkgemit "github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

func TestDetectEmits(t *testing.T) {
	result := stag.EvalResult{
		Verdict: stag.Allow,
		Sinks: []stag.SinkOutcome{
			{Field: "lifecycle.emit.code_fix_required", Verdict: stag.Allow},
			{Field: "lifecycle.normal.field", Verdict: stag.Allow},
			{Field: "lifecycle.emit.docker_rebuild", Verdict: stag.Allow},
		},
	}

	emits := pkgemit.DetectEmits(result)
	if len(emits) != 2 {
		t.Fatalf("expected 2 emit sinks, got %d", len(emits))
	}
	if emits[0].Field != "lifecycle.emit.code_fix_required" {
		t.Errorf("first emit field = %q, want lifecycle.emit.code_fix_required", emits[0].Field)
	}
	if emits[1].Field != "lifecycle.emit.docker_rebuild" {
		t.Errorf("second emit field = %q, want lifecycle.emit.docker_rebuild", emits[1].Field)
	}
}

func TestValidateEmit_Valid(t *testing.T) {
	tests := []struct {
		name  string
		emit  pkgemit.Emit
	}{
		{
			name: "simple emit",
			emit: pkgemit.Emit{
				SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.code_fix_required", Verdict: stag.Allow},
				SlotValue:   `{}`,
			},
		},
		{
			name: "emit with underscores",
			emit: pkgemit.Emit{
				SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.docker_rebuild_required", Verdict: stag.Allow},
				SlotValue:   "",
			},
		},
		{
			name: "emit with numbers",
			emit: pkgemit.Emit{
				SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.event123", Verdict: stag.Allow},
				SlotValue:   `{"x":1}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := pkgemit.ValidateEmit(tt.emit); err != nil {
				t.Errorf("ValidateEmit() = %v, want nil", err)
			}
		})
	}
}

func TestValidateEmit_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		emit    pkgemit.Emit
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing prefix",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "code_fix_required", Verdict: stag.Allow}},
			wantErr: true,
			errMsg:  "must start with lifecycle.emit.",
		},
		{
			name:    "empty kind",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.", Verdict: stag.Allow}},
			wantErr: true,
			errMsg:  "empty kind",
		},
		{
			name:    "invalid kind (starts with number)",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.123event", Verdict: stag.Allow}},
			wantErr: true,
			errMsg:  "not a valid identifier",
		},
		{
			name:    "invalid kind (contains uppercase)",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.CodeFix", Verdict: stag.Allow}},
			wantErr: true,
			errMsg:  "not a valid identifier",
		},
		{
			name:    "invalid kind (contains hyphen)",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.code-fix", Verdict: stag.Allow}},
			wantErr: true,
			errMsg:  "not a valid identifier",
		},
		{
			name:    "non-allow verdict",
			emit:    pkgemit.Emit{SinkOutcome: stag.SinkOutcome{Field: "lifecycle.emit.code_fix_required", Verdict: stag.Deny}},
			wantErr: true,
			errMsg:  "must be Allow",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pkgemit.ValidateEmit(tt.emit)
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateEmit() = %v, want nil", err)
			}
			if tt.wantErr && err == nil {
				t.Errorf("ValidateEmit() = nil, want error containing %q", tt.errMsg)
			}
			if tt.wantErr && err != nil && !contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateEmit() error = %v, want to contain %q", err, tt.errMsg)
			}
		})
	}
}

func TestNewEmittedEvent(t *testing.T) {
	emit := pkgemit.Emit{
		SinkOutcome: stag.SinkOutcome{
			Field:   "lifecycle.emit.code_fix_required",
			Verdict: stag.Allow,
		},
		SlotValue: `{"repo":"lifecycle-demo","findings":[]}`,
	}

	evt := pkgemit.NewEmittedEvent("evt_001", emit, 1)

	if evt.Source != "orchestration" {
		t.Errorf("Source = %q, want orchestration", evt.Source)
	}
	if evt.Type != "code_fix_required" {
		t.Errorf("Type = %q, want code_fix_required", evt.Type)
	}
	if string(evt.Payload) != emit.SlotValue {
		t.Errorf("Payload = %q, want %q", evt.Payload, emit.SlotValue)
	}
	if !evt.Attributed {
		t.Error("Attributed = false, want true")
	}
	if evt.AuthMethod != "recipe_eval" {
		t.Errorf("AuthMethod = %q, want recipe_eval", evt.AuthMethod)
	}
	if evt.ID != "evt_001__emit_1" {
		t.Errorf("ID = %q, want evt_001__emit_1", evt.ID)
	}
}

func TestToDispatchEvent(t *testing.T) {
	evt := pkgemit.EmittedEvent{
		Source:  "orchestration",
		Type:    "code_fix_required",
		Payload: []byte(`{"repo":"demo","findings":[]}`),
	}

	d := evt.ToDispatchEvent()

	if d["source"] != "orchestration" {
		t.Errorf("dispatch event source = %v, want orchestration", d["source"])
	}
	if d["kind"] != "code_fix_required" {
		t.Errorf("dispatch event kind = %v, want code_fix_required", d["kind"])
	}

	// Payload should be parsed JSON
	payload, ok := d["payload"].(map[string]any)
	if !ok {
		t.Fatalf("dispatch event payload is not map[string]any: %T", d["payload"])
	}
	if payload["repo"] != "demo" {
		t.Errorf("payload repo = %v, want demo", payload["repo"])
	}
}

func TestToDispatchEvent_EmptyPayload(t *testing.T) {
	evt := pkgemit.EmittedEvent{
		Source:  "orchestration",
		Type:    "workflow_complete",
		Payload: []byte(""),
	}

	d := evt.ToDispatchEvent()

	if _, ok := d["payload"]; ok {
		t.Error("dispatch event has payload key when payload was empty")
	}
}

func TestIsValidEventKind(t *testing.T) {
	tests := []struct {
		kind  string
		valid bool
	}{
		{"code_fix_required", true},
		{"docker_rebuild", true},
		{"event", true},
		{"e", true},
		{"code_fix_1", true},
		{"a_1_b_2_c", true},
		{"", false},
		{"CodeFix", false},
		{"code-fix", false},
		{"code.fix", false},
		{"1code", false},
		{"_code", false},
		{strings.Repeat("a", 65), false}, // too long
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			if got := pkgemit.IsValidEventKind(tt.kind); got != tt.valid {
				t.Errorf("IsValidEventKind(%q) = %v, want %v", tt.kind, got, tt.valid)
			}
		})
	}
}

// helper
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// Test round-trip: detect -> validate -> emit -> dispatch
func TestRoundTrip(t *testing.T) {
	// Simulate recipe evaluation that emitted an event
	result := stag.EvalResult{
		Verdict: stag.Allow,
		Sinks: []stag.SinkOutcome{
			{
				Field:   "lifecycle.emit.code_fix_required",
				Verdict: stag.Allow,
			},
		},
	}

	// 1. Detect
	sinkOuts := pkgemit.DetectEmits(result)
	if len(sinkOuts) == 0 {
		t.Fatal("no emits detected")
	}

	// 2. Create emit with slot value
	emit := pkgemit.Emit{
		SinkOutcome: sinkOuts[0],
		SlotValue:   `{"repo":"demo","findings":["sql_injection"]}`,
	}

	// 3. Validate
	if err := pkgemit.ValidateEmit(emit); err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// 4. Create emitted event
	evt := pkgemit.NewEmittedEvent("evt_001", emit, 1)
	if evt.Source != "orchestration" {
		t.Errorf("Source = %q, want orchestration", evt.Source)
	}

	// 5. Convert to dispatch event
	dispatchEvt := evt.ToDispatchEvent()
	if dispatchEvt["source"] != "orchestration" {
		t.Errorf("dispatch source = %v, want orchestration", dispatchEvt["source"])
	}
	if dispatchEvt["kind"] != "code_fix_required" {
		t.Errorf("dispatch kind = %v, want code_fix_required", dispatchEvt["kind"])
	}

	// 6. Verify payload is accessible
	payload, ok := dispatchEvt["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload not accessible as map")
	}
	if repo := payload["repo"]; repo != "demo" {
		t.Errorf("payload repo = %v, want demo", repo)
	}
}
