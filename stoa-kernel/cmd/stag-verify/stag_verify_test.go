package main

// kw-test: sniff decision ingress read three-shapes unknown-shape empty tamper-safe

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

// buildDecisionLog writes one leaf in the ORIGINAL, hand-written egress.Leaf shape ("decision").
func buildDecisionLog(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	sink := egress.NewJSONLSink(&buf)
	rec := stag.DecisionRecord{Tool: "kube__get_pods", Verdict: "allow", Forwarded: true, Recipe: "k8s_read_policy"}
	if err := sink.Record(context.Background(), rec); err != nil {
		t.Fatalf("write decision leaf: %v", err)
	}
	return buf.Bytes()
}

// buildIngressLog writes one leaf via the GENERIC chain with T=ingress.Record ("record", disposition-shaped).
func buildIngressLog(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	c := egress.NewChain[ingress.Record](&buf)
	rec := ingress.Record{ID: "abc", Source: "kube", Attributed: true, AuthMethod: "hmac", Disposition: "dispatched:x"}
	if err := c.Append(rec); err != nil {
		t.Fatalf("append ingress leaf: %v", err)
	}
	return buf.Bytes()
}

// buildReadLog writes one leaf via the GENERIC chain with T=provider.ReadEvent ("record", provider-shaped).
func buildReadLog(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	c := egress.NewChain[provider.ReadEvent](&buf)
	rec := provider.ReadEvent{Provider: "runbooks", Query: "q", Items: 2}
	if err := c.Append(rec); err != nil {
		t.Fatalf("append read leaf: %v", err)
	}
	return buf.Bytes()
}

// TestSniffKindDistinguishesAllThreeShapes is the regression this whole fix exists for: stag-verify
// was hardcoded to ONE leaf shape (egress.Leaf, "decision") while a second, GENERIC chain type
// (chain.go's Chain[T]) grew two more log kinds — reads.jsonl and ingress.jsonl — both keyed
// "record", disambiguated only by the record's OWN fields. A regression here silently narrows
// "verify the audit yourself" back down to "verify the decision log only".
func TestSniffKindDistinguishesAllThreeShapes(t *testing.T) {
	cases := []struct {
		name string
		log  []byte
		want logKind
	}{
		{"decision log", buildDecisionLog(t), kindDecision},
		{"ingress log (record/disposition)", buildIngressLog(t), kindIngress},
		{"read log (record/provider)", buildReadLog(t), kindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sniffKind(tc.log)
			if err != nil {
				t.Fatalf("sniffKind: %v", err)
			}
			if got != tc.want {
				t.Errorf("sniffKind = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSniffKindEmptyLogIsHarmless(t *testing.T) {
	got, err := sniffKind(nil)
	if err != nil {
		t.Fatalf("sniffKind(empty): %v", err)
	}
	if got != kindDecision {
		t.Errorf("empty log defaulted to %v, want kindDecision (the harmless default)", got)
	}
}

// A "record" leaf whose fields match NEITHER known record type must be refused, not silently
// misread as one of them — a wrong guess here would verify the wrong hash function and either
// crash or (worse) falsely report CHAIN INTACT / CHAIN BROKEN for the wrong reason.
func TestSniffKindRefusesUnrecognizedRecordShape(t *testing.T) {
	line := []byte(`{"seq":0,"prev_hash":"","record":{"totally":"unknown"},"hash":"x"}` + "\n")
	if _, err := sniffKind(line); err == nil {
		t.Fatal("an unrecognized record shape must be refused, not guessed at")
	}
}

func TestSniffKindRefusesNonLeafJSON(t *testing.T) {
	line := []byte(`{"not":"a leaf"}` + "\n")
	if _, err := sniffKind(line); err == nil {
		t.Fatal("JSON with neither \"decision\" nor \"record\" must be refused")
	}
}

// End-to-end: each real log type must round-trip through VerifyChain with the kind sniffKind picked,
// so the fix is not just "guesses the right label" but "actually verifies the right way".
func TestEndToEndVerifyEachKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  []byte
	}{
		{"decision", buildDecisionLog(t)},
		{"ingress", buildIngressLog(t)},
		{"read", buildReadLog(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, err := sniffKind(tc.log)
			if err != nil {
				t.Fatalf("sniff: %v", err)
			}
			var verr error
			switch kind {
			case kindDecision:
				_, verr = egress.Verify(bytes.NewReader(tc.log))
			case kindIngress:
				_, verr = egress.VerifyChain[ingress.Record](bytes.NewReader(tc.log))
			case kindRead:
				_, verr = egress.VerifyChain[provider.ReadEvent](bytes.NewReader(tc.log))
			}
			if verr != nil {
				t.Fatalf("verify (kind=%v): %v", kind, verr)
			}
		})
	}
}

// A tampered leaf of any of the three kinds must still fail closed — the fix must not weaken
// tamper-evidence while widening what it can read.
func TestTamperingStillDetectedInAllThreeKinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  []byte
		kind logKind
	}{
		{"decision", buildDecisionLog(t), kindDecision},
		{"ingress", buildIngressLog(t), kindIngress},
		{"read", buildReadLog(t), kindRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var leaf map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(tc.log), &leaf); err != nil {
				t.Fatalf("unmarshal leaf: %v", err)
			}
			leaf["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
			tampered, _ := json.Marshal(leaf)
			tampered = append(tampered, '\n')

			kind, err := sniffKind(tampered)
			if err != nil {
				t.Fatalf("sniff tampered: %v", err)
			}
			if kind != tc.kind {
				t.Fatalf("sniff picked %v for a tampered %s leaf, want %v", kind, tc.name, tc.kind)
			}
			var verr error
			switch kind {
			case kindDecision:
				_, verr = egress.Verify(bytes.NewReader(tampered))
			case kindIngress:
				_, verr = egress.VerifyChain[ingress.Record](bytes.NewReader(tampered))
			case kindRead:
				_, verr = egress.VerifyChain[provider.ReadEvent](bytes.NewReader(tampered))
			}
			if verr == nil {
				t.Fatalf("a hash-tampered %s leaf verified as intact", tc.name)
			}
		})
	}
}
