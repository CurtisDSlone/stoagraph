package emit_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestExtractSinksFromResult(t *testing.T) {
	tests := []struct {
		name      string
		res       *mcp.CallToolResult
		wantSink  int
		wantField string
	}{
		{
			name:     "empty result",
			res:      nil,
			wantSink: 0,
		},
		{
			name:     "result with no meta",
			res:      &mcp.CallToolResult{},
			wantSink: 0,
		},
		{
			name: "result with sinks in meta",
			res: &mcp.CallToolResult{
				Meta: mcp.Meta{
					"stag": map[string]any{
						"sinks": []map[string]any{
							{
								"field":   "lifecycle.emit.code_fix_required",
								"verdict": "Allow",
								"arg":     "decision",
							},
						},
					},
				},
			},
			wantSink:  1,
			wantField: "lifecycle.emit.code_fix_required",
		},
		{
			name: "result with multiple sinks",
			res: &mcp.CallToolResult{
				Meta: mcp.Meta{
					"stag": map[string]any{
						"sinks": []map[string]any{
							{
								"field":   "lifecycle.emit.code_fix_required",
								"verdict": "Allow",
							},
							{
								"field":   "lifecycle.emit.docker_rebuild",
								"verdict": "Allow",
							},
						},
					},
				},
			},
			wantSink: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := emit.ExtractSinksFromResult(tt.res)
			if len(got) != tt.wantSink {
				t.Errorf("extracted %d sinks, want %d", len(got), tt.wantSink)
			}
			if len(got) > 0 && tt.wantField != "" {
				if field, ok := got[0]["field"].(string); !ok || field != tt.wantField {
					t.Errorf("first sink field = %v, want %q", got[0]["field"], tt.wantField)
				}
			}
		})
	}
}

func TestSinkCollector(t *testing.T) {
	sc := emit.SinkCollector{}

	// Add first batch
	sc.Add([]map[string]any{
		{"field": "lifecycle.emit.event1", "verdict": "Allow"},
	})

	if len(sc.All()) != 1 {
		t.Errorf("after first Add: %d sinks, want 1", len(sc.All()))
	}

	// Add second batch
	sc.Add([]map[string]any{
		{"field": "lifecycle.emit.event2", "verdict": "Allow"},
		{"field": "lifecycle.emit.event3", "verdict": "Allow"},
	})

	if len(sc.All()) != 3 {
		t.Errorf("after second Add: %d sinks, want 3", len(sc.All()))
	}

	// Add empty batch
	sc.Add(nil)
	if len(sc.All()) != 3 {
		t.Errorf("after empty Add: %d sinks, want 3", len(sc.All()))
	}
}

func TestEmitFromMetadata(t *testing.T) {
	e, ok := emit.EmitFromMetadata(map[string]any{
		"field": "lifecycle.emit.code_fix_required", "verdict": "allow", "arg": "decision",
	}, `{"a":1}`)
	if !ok {
		t.Fatal("valid emit metadata was rejected")
	}
	if e.SinkOutcome.Verdict != stag.Allow {
		t.Errorf("verdict = %v, want Allow", e.SinkOutcome.Verdict)
	}
	if e.SlotValue != `{"a":1}` {
		t.Errorf("slot value not carried: %q", e.SlotValue)
	}
	if err := emit.ValidateEmit(e); err != nil {
		t.Errorf("round-trip failed validation: %v", err)
	}
}

func TestEmitFromMetadataSkipsNonEmitSinks(t *testing.T) {
	if _, ok := emit.EmitFromMetadata(map[string]any{"field": "lifecycle.normal.field"}, ""); ok {
		t.Error("non-emit sink was accepted as an emit")
	}
	if _, ok := emit.EmitFromMetadata(map[string]any{}, ""); ok {
		t.Error("metadata with no field was accepted")
	}
}

// An unreadable verdict must NOT become Allow. ValidateEmit then refuses it,
// so a garbled gate response cannot manufacture an emission.
func TestEmitFromMetadataVerdictFailsClosed(t *testing.T) {
	for _, v := range []any{nil, "", "ALLOW", "allowed", "deny", 1} {
		m := map[string]any{"field": "lifecycle.emit.x"}
		if v != nil {
			m["verdict"] = v
		}
		e, ok := emit.EmitFromMetadata(m, "")
		if !ok {
			t.Fatalf("verdict %v: emit unexpectedly rejected at parse", v)
		}
		if e.SinkOutcome.Verdict == stag.Allow {
			t.Errorf("verdict %v became Allow", v)
		}
		if err := emit.ValidateEmit(e); err == nil {
			t.Errorf("verdict %v passed validation", v)
		}
	}
}
