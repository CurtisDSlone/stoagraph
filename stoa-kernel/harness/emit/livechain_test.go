package emit_test

import (
	"context"
	"os"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// This drives the REAL kernel: a recipe parsed from the same YAML the instance holds,
// evaluated by stag.Eval, its sinks read the way mcpgate exposes them, and fed to the
// harness's own ProcessEmitsAfterRun. If any link is wrong, this fails.

func loadPolicy(t *testing.T) stag.Recipe {
	t.Helper()
	src, err := os.ReadFile("testdata/scan_emit_policy.yaml")
	if err != nil {
		t.Fatalf("read recipe: %v", err)
	}
	p, err := recipe.Parse(src)
	if err != nil {
		t.Fatalf("recipe does not parse — it would be rejected by the instance: %v", err)
	}
	return p.Recipe
}

// mcpMeta mirrors mcpgate.withSinks: what the gate actually puts on the wire.
func mcpMeta(res stag.EvalResult) []map[string]any {
	var out []map[string]any
	for _, s := range res.Sinks {
		m := map[string]any{"field": s.Field, "verdict": s.Verdict.String()}
		if s.Arg != "" {
			m["arg"] = s.Arg
		}
		if s.Value != "" && len(s.Field) > 15 && s.Field[:15] == "lifecycle.emit." {
			m["value"] = s.Value
		}
		out = append(out, m)
	}
	return out
}

func TestLiveChain_FindingEmitsFixRequired(t *testing.T) {
	r := loadPolicy(t)
	res := stag.Eval(r, "sql_injection", "hash-test")

	if res.Fault != "" {
		t.Fatalf("recipe faulted: %s", res.Fault)
	}
	if res.Verdict != stag.Allow {
		t.Fatalf("benign emit sink must Allow, got %v", res.Verdict)
	}

	meta := mcpMeta(res)
	t.Logf("gate exposed sinks: %+v", meta)

	var dispatched []map[string]any
	summary, err := emit.ProcessEmitsAfterRun(context.Background(), meta, nil,
		emit.NewOrchestrationContext("evt_scan_001"),
		func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
			dispatched = append(dispatched, evt)
			return true, nil
		})
	if err != nil {
		t.Fatalf("ProcessEmitsAfterRun: %v", err)
	}

	if len(dispatched) != 1 {
		t.Fatalf("dispatched %d events, want 1 (summary %+v)", len(dispatched), summary)
	}
	got := dispatched[0]
	if got["kind"] != "code_fix_required" {
		t.Errorf("kind = %v, want code_fix_required", got["kind"])
	}
	if got["source"] != "orchestration" {
		t.Errorf("source = %v, want orchestration", got["source"])
	}
	if got[emit.TrustKey] != stag.Untrusted.String() {
		t.Errorf("%s = %v, want untrusted", emit.TrustKey, got[emit.TrustKey])
	}
	// The payload is the finding the gate cleared — a closed-set member, carried through.
	if got["payload"] != "sql_injection" {
		t.Errorf("payload = %v, want sql_injection", got["payload"])
	}
	t.Logf("emitted event: %+v", got)
}

func TestLiveChain_CleanScanEmitsCleanKind(t *testing.T) {
	r := loadPolicy(t)
	res := stag.Eval(r, "clean", "hash-test")

	if res.Verdict != stag.Allow {
		t.Fatalf("verdict = %v, want Allow", res.Verdict)
	}

	var kinds []any
	_, err := emit.ProcessEmitsAfterRun(context.Background(), mcpMeta(res), nil,
		emit.NewOrchestrationContext("evt_scan_002"),
		func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
			kinds = append(kinds, evt["kind"])
			return true, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 1 || kinds[0] != "scan_clean" {
		t.Errorf("kinds = %v, want [scan_clean]", kinds)
	}
	t.Logf("clean scan emitted: %v", kinds)
}

// A finding class nobody enumerated must not start a chain on the fix path.
func TestLiveChain_UnknownFindingDoesNotEmitFixRequired(t *testing.T) {
	r := loadPolicy(t)
	res := stag.Eval(r, "totally_novel_thing", "hash-test")

	var kinds []any
	_, err := emit.ProcessEmitsAfterRun(context.Background(), mcpMeta(res), nil,
		emit.NewOrchestrationContext("evt_scan_003"),
		func(ctx context.Context, evt map[string]any, next emit.OrchestrationContext) (bool, error) {
			kinds = append(kinds, evt["kind"])
			return true, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kinds {
		if k == "code_fix_required" {
			t.Error("an unenumerated finding started the fix chain")
		}
	}
	t.Logf("unknown finding emitted: %v", kinds)
}
