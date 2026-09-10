// Package emit (integration.go) bridges emit detection to the harness dispatcher.
//
// When an agent runs and calls tools through stag-proxy, each tool result may contain
// metadata about sinks that the recipe emitted. This module extracts those sinks from
// the MCP result metadata and processes them for re-dispatch as autonomous events.
package emit

// file-kw: emit mcp-result-metadata extract sinks dispatcher-bridge

import (
	"context"
	"encoding/json"
	"strings"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ExtractSinksFromResult reads emit sink metadata from an MCP tool result.
// Sinks are encoded in the result's Meta["stag"]["sinks"] as an array of sink objects.
// Returns nil if no sinks are present.
func ExtractSinksFromResult(res *mcp.CallToolResult) []map[string]any {
	if res == nil || res.Meta == nil {
		return nil
	}
	stagMeta, ok := res.Meta["stag"].(map[string]any)
	if !ok {
		return nil
	}
	sinksRaw, ok := stagMeta["sinks"]
	if !ok {
		return nil
	}
	sinks, ok := sinksRaw.([]map[string]any)
	if !ok {
		// Try unmarshaling from JSON in case it came through as a marshaled string
		sinkJSON, err := json.Marshal(sinksRaw)
		if err != nil {
			return nil
		}
		var sinksList []map[string]any
		if err := json.Unmarshal(sinkJSON, &sinksList); err != nil {
			return nil
		}
		return sinksList
	}
	return sinks
}

// CollectSinksFromSession walks through all the recorded events in a harness session
// and aggregates any sinks emitted by the recipe. This is called after agent.Run() completes
// to gather all sinks from all tool calls made during the agent loop.
//
// In practice, we store sinks as they come through CallTool results, so this is mainly
// a cleanup function that consolidates them. A real implementation would track them
// in a session-level accumulator during the agent loop.
type SinkCollector struct {
	allSinks []map[string]any
}

// Add records a sink from a tool call result.
func (sc *SinkCollector) Add(sinks []map[string]any) {
	if len(sinks) > 0 {
		sc.allSinks = append(sc.allSinks, sinks...)
	}
}

// All returns all collected sinks.
func (sc *SinkCollector) All() []map[string]any {
	return sc.allSinks
}

// EmitFromMetadata builds an Emit from one gate sink-metadata entry plus the slot value
// the harness resolved for it. Returns ok=false when the entry is not an emit sink or is
// missing the field name — a malformed entry is not an emit, it is nothing.
func EmitFromMetadata(m map[string]any, slotValue string) (Emit, bool) {
	// The gate carries the value for emit sinks; an explicit slotValue overrides it
	// (the caller knows something the gate does not). Neither present = empty payload.
	if slotValue == "" {
		if v, ok := m["value"].(string); ok {
			slotValue = v
		}
	}
	field, _ := m["field"].(string)
	if !strings.HasPrefix(field, "lifecycle.emit.") {
		return Emit{}, false
	}
	// Fail closed: only the exact rendering of Allow becomes Allow. An absent,
	// misspelled, or unparseable verdict stays Deny, and ValidateEmit then refuses
	// the emit. stag does not re-export ParseVerdict, so compare the rendering.
	verdict := stag.Deny
	if v, _ := m["verdict"].(string); v == stag.Allow.String() {
		verdict = stag.Allow
	}
	arg, _ := m["arg"].(string)
	return Emit{
		SinkOutcome: stag.SinkOutcome{Field: field, Verdict: verdict, Arg: arg},
		SlotValue:   slotValue,
	}, true
}

// DispatchFunc re-routes one emitted event. It returns whether the event was actually
// dispatched to a recipe (false = no route matched; the chain ends there, not an error).
type DispatchFunc func(ctx context.Context, event map[string]any, oc OrchestrationContext) (dispatched bool, err error)

// ProcessEmitsAfterRun is the harness's orchestration step, run after an agent loop ends.
//
// It turns the gate's emit sinks into events and re-dispatches each one. Ordering matters:
// the DEPTH CHECK comes first and covers the whole batch, because a chain that has already
// run maxEmitDepth hops must not get one more hop per sink. Then each emit is validated
// individually — an invalid emit is skipped and reported, never fatal to its siblings,
// since one bad sink in a recipe should not silently drop the good ones.
//
// Slot values are supplied by the caller keyed by sink field, because the gate exposes WHICH
// fields were sunk but not what was sunk to them: the value lives in the recipe evaluation
// context inside stag-proxy. An absent value binds "" — which is a valid empty payload, not
// an error, so a recipe that emits a bare signal still works.
func ProcessEmitsAfterRun(
	ctx context.Context,
	sinks []map[string]any,
	slotValues map[string]string,
	oc OrchestrationContext,
	dispatch DispatchFunc,
) (EmitSummary, error) {
	if len(sinks) == 0 {
		return EmitSummary{}, nil
	}

	// Depth is checked ONCE for the batch, before anything is built. Checking per-emit would
	// let a fan-out at the limit each take "one more" hop.
	if !oc.CanEmit() {
		return SummarizeEmits(nil, true), nil
	}

	emits := make([]Emit, 0, len(sinks))
	for _, m := range sinks {
		e, ok := EmitFromMetadata(m, slotValues[fieldOf(m)])
		if !ok {
			continue // not an emit sink; the recipe's other sinks are none of our business
		}
		emits = append(emits, e)
	}
	if len(emits) == 0 {
		return EmitSummary{}, nil
	}

	processed := ProcessEmits(emits, oc)
	for i := range processed {
		p := &processed[i]
		if !p.IsValid {
			continue // already carries its Error; reported in the summary
		}
		ok, err := dispatch(ctx, p.DispatchEvent, p.NextContext)
		if err != nil {
			p.IsValid = false
			p.Error = "dispatch: " + err.Error()
			continue
		}
		if !ok {
			// No route matched. Not a failure — an emit nothing listens for is a
			// recipe announcing something this deployment does not act on.
			p.Error = "no route for emitted event"
		}
	}
	return SummarizeEmits(processed, false), nil
}

func fieldOf(m map[string]any) string {
	f, _ := m["field"].(string)
	return f
}
