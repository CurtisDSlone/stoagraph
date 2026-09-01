package recipe_test

import (
	"math"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

func mustParse(t *testing.T, src string) recipe.Parsed {
	t.Helper()
	p, err := recipe.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// A linear recipe = ONE call with two gated args. F(R) = the PRODUCT of admitted-set sizes
// (3 channels * 2 systems = 6 forwarded tuples). CallBits = log2(F+1) folds in the one per-call
// fire/suppress existence outcome: log2(7).
func TestLeakageLinear(t *testing.T) {
	p := mustParse(t, `recipe: linear
version: 1
rules:
  chan.ok: {kind: set_membership, set: ["a", "b", "c"]}
  sys.ok:  {kind: set_membership, set: ["servicenow", "jira"]}
steps:
  - {id: p1, kind: propose, out: channel}
  - {id: s1, kind: sink, in: channel, field: notify.channel, sensitivity: authoritative, rule: chan.ok, actor: "x"}
  - {id: p2, kind: propose, out: system}
  - {id: s2, kind: sink, in: system, field: ticket.system, sensitivity: authoritative, rule: sys.ok, actor: "x"}`)
	r := recipe.Leakage(p.Recipe)
	if r.Unbounded {
		t.Fatalf("linear recipe (all closed sets) must be bounded: %s", r.UnboundedReason)
	}
	if wantF := math.Log2(6); math.Abs(r.ForwardedTuples-wantF) > 1e-9 {
		t.Fatalf("forwarded-tuple bits = %v; want log2(3*2)=%v (choices MULTIPLY)", r.ForwardedTuples, wantF)
	}
	if wantCall := math.Log2(7); math.Abs(r.CallBits-wantCall) > 1e-9 {
		t.Fatalf("call bits = %v; want log2(6+1)=%v (per-call existence)", r.CallBits, wantCall)
	}
}

// The CENTRAL correction the adversarial review found: a branch is a SUM over cases, not a MAX. The
// attacker may drive the model down ANY path, so the observable-transcript count is F_low+F_med+F_high.
// low=3, med=3*2=6, high=4*3*1=12  =>  F=21. That is strictly greater than the single leakiest PATH
// (high=12): log2(21)=4.39 > log2(12)=3.585. A max-over-paths bound would UNDERCOUNT.
func TestLeakageBranchIsSumNotMax(t *testing.T) {
	r := recipe.Leakage(mustParse(t, branchingRecipe).Recipe)
	if r.Unbounded {
		t.Fatalf("branching recipe (all closed sets) must be bounded: %s", r.UnboundedReason)
	}
	wantF := math.Log2(3 + 6 + 12) // SUM over branches
	if math.Abs(r.ForwardedTuples-wantF) > 1e-9 {
		t.Fatalf("branch bound = %v; want log2(21)=%v (sum, not max)", r.ForwardedTuples, wantF)
	}
	if leakiestPath := math.Log2(12); r.ForwardedTuples <= leakiestPath {
		t.Fatalf("sum(%.3f) must exceed the leakiest single path(%.3f) — else it's a max bound", r.ForwardedTuples, leakiestPath)
	}
	t.Logf("triage leaks log2(21)=%.3f forwarded-tuple bits, %.3f call bits", r.ForwardedTuples, r.CallBits)
}

// More action options = a measurably higher bound. Widen the high-path region set 4 -> 8:
// F: 3+6+12=21 -> 3+6+24=33. The bound rises.
func TestLeakageMoreOptionsMoreBits(t *testing.T) {
	narrow := recipe.Leakage(mustParse(t, branchingRecipe).Recipe).ForwardedTuples
	wide := recipe.Leakage(mustParse(t, branchingRecipeWideRegions).Recipe).ForwardedTuples
	if wide <= narrow {
		t.Fatalf("widening the region set 4->8 must increase the bound; narrow=%v wide=%v", narrow, wide)
	}
	if want := math.Log2(33); math.Abs(wide-want) > 1e-9 {
		t.Fatalf("wide bound = %v; want log2(33)=%v", wide, want)
	}
}

// A single FREE-TEXT passthrough field VOIDS the bound: unbounded leakage. This is the tie to the
// coverage contract — a bound exists exactly when every output-reaching argument is closed-set.
func TestLeakagePassthroughVoidsBound(t *testing.T) {
	p := mustParse(t, `recipe: leaky
version: 1
passthrough: ["reason"]
rules:
  chan.ok: {kind: set_membership, set: ["a", "b"]}
steps:
  - {id: p1, kind: propose, out: channel}
  - {id: s1, kind: sink, in: channel, field: notify.channel, sensitivity: authoritative, rule: chan.ok, actor: "x"}`)
	r := recipe.Leakage(p.Recipe)
	if !r.Unbounded {
		t.Fatal("a free-text passthrough field must make the bound UNBOUNDED")
	}
	t.Logf("unbounded, as required: %s", r.UnboundedReason)
}

// signed_equality contributes NO value choice (only the one signed token releases), but the model can
// still FIRE or SUPPRESS the call, and absence is observable — so the CALL carries 1 bit: log2(1+1).
// (The old per-sink model scored this 0; the per-call existence bit is the correction.)
func TestLeakageSignedEqualityOneBit(t *testing.T) {
	p := mustParse(t, `recipe: signed
version: 1
rules:
  tok: {kind: signed_equality, signed: "the-one-token"}
steps:
  - {id: p1, kind: propose, out: v}
  - {id: s1, kind: sink, in: v, field: act.v, sensitivity: authoritative, rule: tok, actor: "x"}`)
	r := recipe.Leakage(p.Recipe)
	if r.Unbounded || math.Abs(r.CallBits-1) > 1e-9 {
		t.Fatalf("signed_equality call = 1 bit (fire/suppress, no value choice); got %v (unbounded=%v)", r.CallBits, r.Unbounded)
	}
	if r.ForwardedTuples != 0 {
		t.Fatalf("signed_equality forwards exactly 1 tuple (log2 1 = 0 value bits); got %v", r.ForwardedTuples)
	}
}

// A GATE-constrained benign sink is NOT free text: the escalate pattern (gate a slot, then benign-sink
// it) forwards a value the gate already bounded, so it is BOUNDED at the gate's set size — not unbounded.
// gate ns.safe (K=2) then benign sink namespace => F=2, CallBits=log2(3).
func TestLeakageGateConstrainsBenignSink(t *testing.T) {
	nsSafe := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"staging", "dev"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "namespace", Goto: "g"},
		{Id: "g", Kind: stag.NodeGate, In: "namespace", Rule: nsSafe, Escalate: true, Goto: "s"},
		{Id: "s", Kind: stag.NodeSink, In: "namespace", Sensitivity: stag.SinkBenign, Field: "scale.ns"},
	}}
	lr := recipe.Leakage(r)
	if lr.Unbounded {
		t.Fatalf("a gate-constrained benign sink is bounded, not free text: %s", lr.UnboundedReason)
	}
	if want := math.Log2(2); math.Abs(lr.ForwardedTuples-want) > 1e-9 {
		t.Fatalf("gated benign sink bound = %v; want log2(2)=%v (the gate's set size)", lr.ForwardedTuples, want)
	}
}

// An UNGATED benign sink IS free text -> unbounded. (Same shape as above, minus the gate.)
func TestLeakageUngatedBenignSinkUnbounded(t *testing.T) {
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "namespace", Goto: "s"},
		{Id: "s", Kind: stag.NodeSink, In: "namespace", Sensitivity: stag.SinkBenign, Field: "scale.ns"},
	}}
	if lr := recipe.Leakage(r); !lr.Unbounded {
		t.Fatal("an ungated benign sink forwards free text and must be UNBOUNDED")
	}
}

// The DOMINANT correction: a foreach body multiplies by a geometric series over the iteration cap, not
// once. Body carries log2(3) bits/element; over 0..64 elements the loop forwards ~3^65 tuples ≈ 102
// bits — the old "walk the body once" scored ~1.585. This is the >100x session-level undercount.
func TestLeakageForeachGeometric(t *testing.T) {
	actOK := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "scale", "clear"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "plan", Goto: "fe"},
		{Id: "fe", Kind: stag.NodeForeach, In: "plan", As: "item", Goto: "act"},
		{Id: "act", Kind: stag.NodeSink, In: "item", Sensitivity: stag.SinkAuthoritative, Rule: actOK, Field: "exec.action", Goto: "done"},
		{Id: "done", Kind: stag.NodeExit},
	}}
	lr := recipe.Leakage(r)
	if lr.Unbounded {
		t.Fatalf("bounded foreach body must stay bounded: %s", lr.UnboundedReason)
	}
	oneIteration := math.Log2(3) // ~1.585
	if lr.ForwardedTuples < 60 || lr.ForwardedTuples <= oneIteration {
		t.Fatalf("foreach must apply the geometric multiplier (~102 bits, >> one iteration %.3f); got %v", oneIteration, lr.ForwardedTuples)
	}
	t.Logf("foreach over %d elements leaks ~%.1f forwarded-tuple bits (one iteration was %.3f)", 64, lr.ForwardedTuples, oneIteration)
}

// Even a single-value (signed) foreach body leaks the LENGTH channel: how many of 0..64 elements fired
// is observable = log2(65) ≈ 6.02 bits, NOT 0.
func TestLeakageForeachLengthChannel(t *testing.T) {
	tok := &stag.ReleaseRule{Kind: stag.RuleSignedEquality, Signed: "approved"}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "plan", Goto: "fe"},
		{Id: "fe", Kind: stag.NodeForeach, In: "plan", As: "item", Goto: "act"},
		{Id: "act", Kind: stag.NodeSink, In: "item", Sensitivity: stag.SinkAuthoritative, Rule: tok, Field: "exec.action", Goto: "done"},
		{Id: "done", Kind: stag.NodeExit},
	}}
	lr := recipe.Leakage(r)
	if want := math.Log2(65); lr.Unbounded || math.Abs(lr.ForwardedTuples-want) > 1e-9 {
		t.Fatalf("single-value foreach leaks the length channel log2(65)=%v; got %v (unbounded=%v)", want, lr.ForwardedTuples, lr.Unbounded)
	}
}

// A wide numeric_range must NOT overflow to 0 bits (adversarial finding: Max-Min+1 wrapped negative and
// scored a ~63-bit channel as 0). [0, MaxInt64] is ~2^63 admitted values ⇒ ~63 bits.
func TestLeakageNumericRangeNoOverflow(t *testing.T) {
	rule := &stag.ReleaseRule{Kind: stag.RuleNumericRange, Min: 0, Max: math.MaxInt64}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "rid", Goto: "s"},
		{Id: "s", Kind: stag.NodeSink, In: "rid", Sensitivity: stag.SinkAuthoritative, Rule: rule, Field: "exec.id", Goto: "done"},
		{Id: "done", Kind: stag.NodeExit},
	}}
	lr := recipe.Leakage(r)
	if lr.Unbounded || lr.ForwardedTuples < 62 || lr.ForwardedTuples > 64 {
		t.Fatalf("full-range numeric leaks ~63 bits (no overflow to 0); got %v (unbounded=%v)", lr.ForwardedTuples, lr.Unbounded)
	}
}

// SessionBound composes the per-session ceiling over the recipes advertised to one session and the
// gate-enforced crossing cap N. Two recipes with F=6 and F=1, no escalation => Ψ=7; N=6 crossings =>
// L = log2(Σ_{t=0}^6 7^t) ≈ 17.07, which sits between N*log2(Ψ)=16.84 and N*log2(Ψ+1)=18.
func TestSessionBound(t *testing.T) {
	linear := mustParse(t, `recipe: linear
version: 1
rules:
  chan.ok: {kind: set_membership, set: ["a", "b", "c"]}
  sys.ok:  {kind: set_membership, set: ["servicenow", "jira"]}
steps:
  - {id: p1, kind: propose, out: channel}
  - {id: s1, kind: sink, in: channel, field: notify.channel, sensitivity: authoritative, rule: chan.ok, actor: "x"}
  - {id: p2, kind: propose, out: system}
  - {id: s2, kind: sink, in: system, field: ticket.system, sensitivity: authoritative, rule: sys.ok, actor: "x"}`)
	signed := mustParse(t, `recipe: signed
version: 1
rules:
  tok: {kind: signed_equality, signed: "the-one-token"}
steps:
  - {id: p1, kind: propose, out: v}
  - {id: s1, kind: sink, in: v, field: act.v, sensitivity: authoritative, rule: tok, actor: "x"}`)
	bits, unbounded, reason := recipe.SessionBound([]stag.Recipe{linear.Recipe, signed.Recipe}, 6)
	if unbounded {
		t.Fatalf("bounded recipe set must give a bounded session: %s", reason)
	}
	lo, hi := 6*math.Log2(7), 6*math.Log2(8) // N*log2(Ψ) .. N*log2(Ψ+1)
	if bits < lo-1e-6 || bits > hi+1e-6 {
		t.Fatalf("session bound = %v; want in [%v, %v]", bits, lo, hi)
	}
	t.Logf("6-crossing session over {linear, signed} leaks at most %.2f bits", bits)
}

// A single unbounded recipe makes the whole advertised session unbounded.
func TestSessionBoundUnboundedIfAnyRecipeIs(t *testing.T) {
	leaky := mustParse(t, `recipe: leaky
version: 1
passthrough: ["reason"]
steps:
  - {id: p1, kind: propose, out: channel}`)
	if _, unbounded, _ := recipe.SessionBound([]stag.Recipe{leaky.Recipe}, 6); !unbounded {
		t.Fatal("a session advertising an unbounded recipe must be unbounded")
	}
}

const branchingRecipe = `recipe: triage
version: 1
rules:
  sev.low:   {kind: set_membership, set: ["low"]}
  sev.high:  {kind: set_membership, set: ["high"]}
  chan.ok:   {kind: set_membership, set: ["soc-alerts", "soc-incidents", "oncall"]}
  region.ok: {kind: set_membership, set: ["us-east", "us-west", "eu-central", "ap-south"]}
  sys.ok:    {kind: set_membership, set: ["servicenow", "jira"]}
  host.appr: {kind: signed_equality, signed: "quarantine-approved"}
steps:
  - {id: p_sev, kind: propose, out: severity}
  - id: route
    kind: branch
    in: severity
    cases:
      - {rule: sev.low, goto: low_ch}
      - {rule: sev.high, goto: hi_region}
    default: med_ch
  - {id: low_ch, kind: propose, out: lc, goto: low_sink}
  - {id: low_sink, kind: sink, in: lc, field: notify.low, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: done}
  - {id: med_ch, kind: propose, out: mc, goto: med_notify}
  - {id: med_notify, kind: sink, in: mc, field: notify.med, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: med_sysp}
  - {id: med_sysp, kind: propose, out: ms, goto: med_ticket}
  - {id: med_ticket, kind: sink, in: ms, field: ticket.med, sensitivity: authoritative, rule: sys.ok, actor: "x", goto: done}
  - {id: hi_region, kind: propose, out: hr, goto: hi_reroute}
  - {id: hi_reroute, kind: sink, in: hr, field: reroute.region, sensitivity: authoritative, rule: region.ok, actor: "x", goto: hi_chp}
  - {id: hi_chp, kind: propose, out: hc, goto: hi_notify}
  - {id: hi_notify, kind: sink, in: hc, field: notify.hi, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: hi_hostp}
  - {id: hi_hostp, kind: propose, out: hh, goto: hi_isolate}
  - {id: hi_isolate, kind: sink, in: hh, field: isolate.host, sensitivity: authoritative, rule: host.appr, actor: "x", goto: done}
  - {id: done, kind: exit}`

const branchingRecipeWideRegions = `recipe: triage
version: 1
rules:
  sev.low:   {kind: set_membership, set: ["low"]}
  sev.high:  {kind: set_membership, set: ["high"]}
  chan.ok:   {kind: set_membership, set: ["soc-alerts", "soc-incidents", "oncall"]}
  region.ok: {kind: set_membership, set: ["us-east", "us-west", "eu-central", "ap-south", "us-north", "eu-west", "ap-east", "sa-east"]}
  sys.ok:    {kind: set_membership, set: ["servicenow", "jira"]}
  host.appr: {kind: signed_equality, signed: "quarantine-approved"}
steps:
  - {id: p_sev, kind: propose, out: severity}
  - id: route
    kind: branch
    in: severity
    cases:
      - {rule: sev.low, goto: low_ch}
      - {rule: sev.high, goto: hi_region}
    default: med_ch
  - {id: low_ch, kind: propose, out: lc, goto: low_sink}
  - {id: low_sink, kind: sink, in: lc, field: notify.low, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: done}
  - {id: med_ch, kind: propose, out: mc, goto: med_notify}
  - {id: med_notify, kind: sink, in: mc, field: notify.med, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: med_sysp}
  - {id: med_sysp, kind: propose, out: ms, goto: med_ticket}
  - {id: med_ticket, kind: sink, in: ms, field: ticket.med, sensitivity: authoritative, rule: sys.ok, actor: "x", goto: done}
  - {id: hi_region, kind: propose, out: hr, goto: hi_reroute}
  - {id: hi_reroute, kind: sink, in: hr, field: reroute.region, sensitivity: authoritative, rule: region.ok, actor: "x", goto: hi_chp}
  - {id: hi_chp, kind: propose, out: hc, goto: hi_notify}
  - {id: hi_notify, kind: sink, in: hc, field: notify.hi, sensitivity: authoritative, rule: chan.ok, actor: "x", goto: hi_hostp}
  - {id: hi_hostp, kind: propose, out: hh, goto: hi_isolate}
  - {id: hi_isolate, kind: sink, in: hh, field: isolate.host, sensitivity: authoritative, rule: host.appr, actor: "x", goto: done}
  - {id: done, kind: exit}`
