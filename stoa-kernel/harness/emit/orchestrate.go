// Package emit (orchestrate.go) handles orchestration context and loop prevention.
//
// This module manages emission chains to prevent infinite loops and tracks
// the orchestration context through recursive recipe invocations.
package emit

// file-kw: emit orchestration-context loop-prevention max-depth chain

import (
	"fmt"
)

const (
	// MaxEmitDepth bounds how many hops one emission chain may take.
	//
	// It is the loop bound: a recipe that emits an event routing back to itself would
	// otherwise run forever, and a chain that fans out would grow without limit. Exported
	// because the harness reports the limit it is enforcing — a chain that stopped must be
	// able to say what stopped it.
	//
	// 10 is chosen for headroom over real workflows (assess → fix → rebuild is 3) while
	// keeping the worst case tractable and auditable.
	MaxEmitDepth = 10
)

// OrchestrationContext tracks an emission chain to prevent infinite loops.
type OrchestrationContext struct {
	SourceEventID string   // original evt_001
	EmitDepth     int      // current depth in emission chain
	EmissionPath  []string // chain of event IDs: [evt_001, evt_002, evt_003...]
}

// NewOrchestrationContext creates a context for the root event.
func NewOrchestrationContext(eventID string) OrchestrationContext {
	return OrchestrationContext{
		SourceEventID: eventID,
		EmitDepth:     0,
		EmissionPath:  []string{eventID},
	}
}

// CanEmit reports whether another emission is permitted (depth check).
func (oc OrchestrationContext) CanEmit() bool {
	return oc.EmitDepth < MaxEmitDepth
}

// NextDepth returns a new context for the next emission in the chain.
func (oc OrchestrationContext) NextDepth(emittedEventID string) OrchestrationContext {
	newPath := make([]string, len(oc.EmissionPath)+1)
	copy(newPath, oc.EmissionPath)
	newPath[len(newPath)-1] = emittedEventID

	return OrchestrationContext{
		SourceEventID: oc.SourceEventID,
		EmitDepth:     oc.EmitDepth + 1,
		EmissionPath:  newPath,
	}
}

// ProcessedEmit is the result of processing an emit sink.
type ProcessedEmit struct {
	IsValid       bool                 // did it pass validation?
	Error         string               // if not valid, why?
	EmittedEvent  EmittedEvent         // the created event
	DispatchEvent map[string]any       // ready for dispatcher routing
	NextContext   OrchestrationContext // context for next emission
}

// ProcessEmits validates and processes a batch of emit sinks.
// Returns only the valid emits that can be dispatched.
func ProcessEmits(emits []Emit, orchestrationCtx OrchestrationContext) []ProcessedEmit {
	if !orchestrationCtx.CanEmit() {
		return nil // depth limit reached
	}

	var results []ProcessedEmit
	eventCounter := int64(0)

	for _, emit := range emits {
		// Validate
		if err := ValidateEmit(emit); err != nil {
			results = append(results, ProcessedEmit{
				IsValid: false,
				Error:   err.Error(),
			})
			continue
		}

		// Create event
		eventCounter++
		eventID := fmt.Sprintf("%s__emit_%d", orchestrationCtx.SourceEventID, eventCounter)
		evt := NewEmittedEvent(orchestrationCtx.SourceEventID, emit, int(eventCounter))
		evt.ID = eventID

		// Convert to dispatch format
		dispatchEvt := evt.ToDispatchEvent()

		// Add orchestration metadata
		dispatchEvt["_emit_depth"] = orchestrationCtx.EmitDepth + 1
		dispatchEvt["_source_event"] = orchestrationCtx.SourceEventID

		// Prepare context for next recursion
		nextCtx := orchestrationCtx.NextDepth(eventID)

		results = append(results, ProcessedEmit{
			IsValid:       true,
			EmittedEvent:  evt,
			DispatchEvent: dispatchEvt,
			NextContext:   nextCtx,
		})
	}

	return results
}

// EmitSummary reports on a batch of processed emits.
type EmitSummary struct {
	Total       int
	Valid       int
	Invalid     int
	Blocked     bool // due to depth limit
	BlockReason string
}

// SummarizeEmits creates a summary of emission processing.
func SummarizeEmits(processed []ProcessedEmit, depthLimited bool) EmitSummary {
	valid := 0
	invalid := 0
	for _, p := range processed {
		if p.IsValid {
			valid++
		} else {
			invalid++
		}
	}

	return EmitSummary{
		Total:       len(processed),
		Valid:       valid,
		Invalid:     invalid,
		Blocked:     depthLimited,
		BlockReason: fmt.Sprintf("emit depth exceeds %d", MaxEmitDepth),
	}
}
