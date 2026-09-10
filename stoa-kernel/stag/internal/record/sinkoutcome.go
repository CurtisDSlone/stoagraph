package record

// file-kw: sink outcome audit record per-sink verdict field actor

import (
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

// SinkOutcome is the audit-facing half of a per-sink evaluation: what the sink was, and what
// happened at it. Unlike ReleaseEvent (a RELEASE — an actual crossing), a SinkOutcome exists for
// every sink a recipe evaluates, denied or escalated ones included, which is why DecisionRecord
// carries it under the same Forwarded gate as Events: the record states what happened, and a sink
// on a call that never reached the tool did not happen either.
type SinkOutcome struct {
	Field    string
	Subject  trust.TrustClass
	Sink     gate.SinkSensitivity
	Released bool
	Verdict  gate.Verdict
	Arg      string
	RuleID   string
	// Actor is the step's declared actor; empty for a benign sink (never legal there — see
	// stag.Step.Actor), present whenever the sink has a rule.
	Actor string
}
