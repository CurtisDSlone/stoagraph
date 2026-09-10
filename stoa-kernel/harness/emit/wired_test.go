package emit_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// These drive ProcessEmitsAfterRun — the function the harness actually calls — with a
// dispatch callback that records hops. Unlike hand-walking NextDepth(), a failure here
// means the ENFORCEMENT is broken, not just the arithmetic.

func sinkMeta(kind string) map[string]any {
	return map[string]any{
		"field":   "lifecycle.emit." + kind,
		"verdict": stag.Allow.String(),
	}
}

// A recipe that emits an event routing back to itself. The chain must terminate.
func TestWiredSelfReferenceTerminates(t *testing.T) {
	var hops []string
	oc := emit.NewOrchestrationContext("evt_001")

	var run func(context.Context, emit.OrchestrationContext)
	run = func(ctx context.Context, cur emit.OrchestrationContext) {
		// every hop emits the same kind — routing back to itself
		_, err := emit.ProcessEmitsAfterRun(ctx, []map[string]any{sinkMeta("code_fix_required")}, nil, cur,
			func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
				hops = append(hops, fmt.Sprintf("%v@%d", evt["kind"], next.EmitDepth))
				if len(hops) > 100 {
					t.Fatal("chain did not terminate — loop prevention is not enforced")
				}
				run(ctx, next)
				return true, nil
			})
		if err != nil {
			t.Fatalf("ProcessEmitsAfterRun: %v", err)
		}
	}
	run(context.Background(), oc)

	if len(hops) != emit.MaxEmitDepth {
		t.Errorf("chain took %d hops, want exactly %d (MaxEmitDepth)", len(hops), emit.MaxEmitDepth)
	}
	t.Logf("self-referential chain terminated after %d hops", len(hops))
}

// Fan-out: each hop emits TWO events. Without a batch-level depth check this would
// grow exponentially. Assert the total stays polynomial, and record the real number.
func TestWiredFanOutIsBounded(t *testing.T) {
	total := 0
	var run func(context.Context, emit.OrchestrationContext)
	run = func(ctx context.Context, cur emit.OrchestrationContext) {
		_, err := emit.ProcessEmitsAfterRun(ctx,
			[]map[string]any{sinkMeta("slack_notify"), sinkMeta("email_notify")}, nil, cur,
			func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
				total++
				if total > 10000 {
					t.Fatal("fan-out unbounded")
				}
				run(ctx, next)
				return true, nil
			})
		if err != nil {
			t.Fatalf("ProcessEmitsAfterRun: %v", err)
		}
	}
	run(context.Background(), emit.NewOrchestrationContext("evt_001"))

	// 2 emits per level over MaxEmitDepth levels: 2^10 - 2 = 2046 with a per-branch
	// depth counter. Exponential in depth but BOUNDED, and the bound is what matters.
	t.Logf("fan-out chain produced %d events, bounded at depth %d", total, emit.MaxEmitDepth)
	if total == 0 {
		t.Fatal("no events dispatched")
	}
	if total > 1<<(emit.MaxEmitDepth+1) {
		t.Errorf("fan-out exceeded its depth bound: %d events", total)
	}
}

// The depth check covers the BATCH, not each emit: a chain already at the limit must
// not get one extra hop per sink.
func TestWiredDepthCheckIsBatchLevel(t *testing.T) {
	atLimit := emit.OrchestrationContext{
		SourceEventID: "evt_001",
		EmitDepth:     emit.MaxEmitDepth,
		EmissionPath:  []string{"evt_001"},
	}
	dispatched := 0
	summary, err := emit.ProcessEmitsAfterRun(context.Background(),
		[]map[string]any{sinkMeta("a"), sinkMeta("b"), sinkMeta("c")}, nil, atLimit,
		func(context.Context, map[string]any, emit.OrchestrationContext) (bool, error) {
			dispatched++
			return true, nil
		})
	if err != nil {
		t.Fatalf("ProcessEmitsAfterRun: %v", err)
	}
	if dispatched != 0 {
		t.Errorf("%d event(s) dispatched at the depth limit, want 0", dispatched)
	}
	if !summary.Blocked {
		t.Error("summary should report the chain as blocked")
	}
}

// An emit nothing routes to ends the chain quietly — not an error, and it must not
// stop its siblings from dispatching.
func TestWiredUnroutedEmitEndsChainQuietly(t *testing.T) {
	routed := 0
	summary, err := emit.ProcessEmitsAfterRun(context.Background(),
		[]map[string]any{sinkMeta("has_route"), sinkMeta("no_route")}, nil,
		emit.NewOrchestrationContext("evt_001"),
		func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
			if evt["kind"] == "no_route" {
				return false, nil
			}
			routed++
			return true, nil
		})
	if err != nil {
		t.Fatalf("unrouted emit should not be an error: %v", err)
	}
	if routed != 1 {
		t.Errorf("routed %d, want 1 — an unrouted sibling blocked a routed emit", routed)
	}
	if summary.Total != 2 {
		t.Errorf("summary.Total = %d, want 2", summary.Total)
	}
}

// A dispatch error on one emit must not abort its siblings.
func TestWiredDispatchErrorIsPerEmit(t *testing.T) {
	ok := 0
	summary, err := emit.ProcessEmitsAfterRun(context.Background(),
		[]map[string]any{sinkMeta("bad"), sinkMeta("good")}, nil,
		emit.NewOrchestrationContext("evt_001"),
		func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
			if evt["kind"] == "bad" {
				return false, fmt.Errorf("route lookup failed")
			}
			ok++
			return true, nil
		})
	if err != nil {
		t.Fatalf("per-emit error should not fail the batch: %v", err)
	}
	if ok != 1 {
		t.Errorf("dispatched %d good emit(s), want 1", ok)
	}
	if summary.Invalid != 1 {
		t.Errorf("summary.Invalid = %d, want 1", summary.Invalid)
	}
}

// An oversize payload is refused at the wired boundary, not just by ValidateEmit
// in isolation.
func TestWiredOversizePayloadIsNotDispatched(t *testing.T) {
	big := make([]byte, emit.DefaultMaxPayloadBytes+1)
	for i := range big {
		big[i] = 'A'
	}
	dispatched := 0
	summary, err := emit.ProcessEmitsAfterRun(context.Background(),
		[]map[string]any{sinkMeta("code_fix_required")},
		map[string]string{"lifecycle.emit.code_fix_required": string(big)},
		emit.NewOrchestrationContext("evt_001"),
		func(context.Context, map[string]any, emit.OrchestrationContext) (bool, error) {
			dispatched++
			return true, nil
		})
	if err != nil {
		t.Fatalf("ProcessEmitsAfterRun: %v", err)
	}
	if dispatched != 0 {
		t.Error("oversize payload was dispatched")
	}
	if summary.Invalid != 1 {
		t.Errorf("summary.Invalid = %d, want 1", summary.Invalid)
	}
}
