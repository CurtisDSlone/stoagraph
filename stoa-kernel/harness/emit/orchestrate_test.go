package emit_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

func TestOrchestrationContext_CanEmit(t *testing.T) {
	tests := []struct {
		depth int
		want  bool
	}{
		{0, true},
		{5, true},
		{9, true},
		{10, false}, // at limit
		{11, false}, // over limit
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.depth+'0')), func(t *testing.T) {
			oc := emit.OrchestrationContext{EmitDepth: tt.depth}
			if got := oc.CanEmit(); got != tt.want {
				t.Errorf("CanEmit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrchestrationContext_NextDepth(t *testing.T) {
	oc := emit.NewOrchestrationContext("evt_001")
	if oc.EmitDepth != 0 {
		t.Fatalf("initial depth = %d, want 0", oc.EmitDepth)
	}
	if len(oc.EmissionPath) != 1 || oc.EmissionPath[0] != "evt_001" {
		t.Fatalf("initial path = %v, want [evt_001]", oc.EmissionPath)
	}

	// First emission
	next1 := oc.NextDepth("evt_002")
	if next1.EmitDepth != 1 {
		t.Errorf("next1.EmitDepth = %d, want 1", next1.EmitDepth)
	}
	if len(next1.EmissionPath) != 2 || next1.EmissionPath[1] != "evt_002" {
		t.Errorf("next1.EmissionPath = %v, want [evt_001 evt_002]", next1.EmissionPath)
	}

	// Second emission (from first)
	next2 := next1.NextDepth("evt_003")
	if next2.EmitDepth != 2 {
		t.Errorf("next2.EmitDepth = %d, want 2", next2.EmitDepth)
	}
	if len(next2.EmissionPath) != 3 {
		t.Errorf("next2.EmissionPath length = %d, want 3", len(next2.EmissionPath))
	}

	// Original unchanged
	if oc.EmitDepth != 0 {
		t.Errorf("original depth modified to %d", oc.EmitDepth)
	}
}

func TestProcessEmits(t *testing.T) {
	emits := []emit.Emit{
		{
			SinkOutcome: stag.SinkOutcome{
				Field:   "lifecycle.emit.code_fix_required",
				Verdict: stag.Allow,
			},
			SlotValue: `{}`,
		},
		{
			SinkOutcome: stag.SinkOutcome{
				Field:   "lifecycle.normal.field", // not an emit
				Verdict: stag.Allow,
			},
			SlotValue: `{}`,
		},
	}

	orchestrationCtx := emit.NewOrchestrationContext("evt_001")
	processed := emit.ProcessEmits(emits, orchestrationCtx)

	if len(processed) != 2 {
		t.Fatalf("processed %d emits, want 2", len(processed))
	}

	// First should be valid
	if !processed[0].IsValid {
		t.Errorf("first emit should be valid, got error: %s", processed[0].Error)
	}
	if processed[0].EmittedEvent.Type != "code_fix_required" {
		t.Errorf("first emit type = %q, want code_fix_required", processed[0].EmittedEvent.Type)
	}

	// Second should be invalid
	if processed[1].IsValid {
		t.Errorf("second emit should be invalid (not an emit field)")
	}
}

func TestProcessEmits_DepthLimit(t *testing.T) {
	emits := []emit.Emit{
		{
			SinkOutcome: stag.SinkOutcome{
				Field:   "lifecycle.emit.event",
				Verdict: stag.Allow,
			},
			SlotValue: `{}`,
		},
	}

	// At depth limit
	orchestrationCtx := emit.OrchestrationContext{
		SourceEventID: "evt_001",
		EmitDepth:     emit.MaxEmitDepth,
		EmissionPath:  []string{"evt_001"},
	}

	processed := emit.ProcessEmits(emits, orchestrationCtx)

	if len(processed) != 0 {
		t.Errorf("should return no results at depth limit, got %d", len(processed))
	}
}

func TestSummarizeEmits(t *testing.T) {
	processed := []emit.ProcessedEmit{
		{IsValid: true},
		{IsValid: true},
		{IsValid: false, Error: "bad field"},
	}

	summary := emit.SummarizeEmits(processed, false)

	if summary.Total != 3 {
		t.Errorf("Total = %d, want 3", summary.Total)
	}
	if summary.Valid != 2 {
		t.Errorf("Valid = %d, want 2", summary.Valid)
	}
	if summary.Invalid != 1 {
		t.Errorf("Invalid = %d, want 1", summary.Invalid)
	}
	if summary.Blocked {
		t.Errorf("Blocked = true, want false")
	}
}
