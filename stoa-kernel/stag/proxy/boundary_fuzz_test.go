package proxy_test

// FuzzGateBoundary — the boundary invariant as a native Go fuzz target (run:
//   go test -run x -fuzz FuzzGateBoundary ./stag/proxy         # deep exploration
//   go test ./stag/proxy                                        # seed corpus, in CI).
//
// It mutates (tool, rawArgs) — the exact wire a hostile MCP client controls — and asserts, for EVERY
// input the fuzzer can find, the decision-core invariants that make "0% forbidden crossing" true:
//   1. Forward happens IFF the verdict is Allow (no forward on deny/escalate/fault).
//   2. Only a ROUTED tool ever forwards (unknown/unrouted tools fail closed).
//   3. A forwarded value is POLICY-COMPLIANT — a set member, or a canonical integer in range. This is the
//      one that catches a canonicalization hole: if " eu-central" or "05" ever forwarded, the released
//      value would not be a canonical member and this fires.
//   4. Every decision records EXACTLY ONE audit leaf.
// The fuzzer needs no downstream: at the decision core, "forwarded" = Verdict==Allow, and invariant 3
// checks the released value directly, so any value that should not cross is caught here fast.
//
// SCOPE (adversarially reviewed 2026-07-15): invariant 3 reads dec.Value (the audit rendering), which
// equals the forwarded value ONLY for a single-scalar GateArg — which is what this fuzzes. It is sound
// there and does NOT generalize to multi-arg / composite-array / passthrough routes; the end-to-end
// TestHostileClientZeroCross covers the array-path rollup against the real transport. TestGateBoundaryLiveness
// below is the anti-vacuity guard: without it, a brick (all-deny) gate would satisfy every invariant here.

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

type countSink struct{ n int }

func (c *countSink) Record(context.Context, stag.DecisionRecord) error { c.n++; return nil }

// TestGateBoundaryLiveness is the anti-vacuity guard for FuzzGateBoundary: its invariants all sit behind
// `if !dec.Forward { return }`, so a brick gate that denies everything would pass the fuzz trivially. This
// asserts the in-policy values actually FORWARD — so the fuzz's "nothing bad crosses" means something.
func TestGateBoundaryLiveness(t *testing.T) {
	reroute := mustParseRecipe(t, rerouteSrc)
	replicas := mustParseRecipe(t, replicasSrc)
	rerouteTool := proxy.AdvertisedName("srv", "reroute")
	replicasTool := proxy.AdvertisedName("srv", "replicas")
	gate := proxy.Gate{Routes: proxy.Router{
		rerouteTool:  {Recipe: reroute.Recipe, RecipeHash: reroute.SemanticHash, GateArg: "target", Server: "srv", Tool: "reroute"},
		replicasTool: {Recipe: replicas.Recipe, RecipeHash: replicas.SemanticHash, GateArg: "count", Server: "srv", Tool: "replicas"},
	}}
	for _, c := range []struct{ tool, args, val string }{
		{rerouteTool, `{"target":"eu-central"}`, "eu-central"},
		{replicasTool, `{"count":"5"}`, "5"},
	} {
		d := gate.Decide(context.Background(), proxy.ToolCall{Tool: c.tool, Raw: json.RawMessage(c.args)})
		if !d.Forward || d.Verdict != stag.Allow || d.Value != c.val {
			t.Fatalf("liveness: %s must forward %q; got %+v (a brick gate would fail here)", c.tool, c.val, d)
		}
	}
}

func mustParseRecipe(t *testing.T, src string) recipe.Parsed {
	t.Helper()
	p, err := recipe.Parse([]byte(src))
	if err != nil {
		t.Fatalf("recipe: %v", err)
	}
	return p
}

const rerouteSrc = `recipe: reroute
version: 1
rules:
  tgt.ok: {kind: set_membership, set: ["eu-central", "us-east", "us-west"]}
steps:
  - {id: p, kind: propose, out: target}
  - {id: s, kind: sink, in: target, field: net.reroute, sensitivity: authoritative, rule: tgt.ok, actor: "policy:x"}`

const replicasSrc = `recipe: replicas
version: 1
rules:
  reps.ok: {kind: numeric_range, min: 1, max: 10}
steps:
  - {id: p, kind: propose, out: count}
  - {id: s, kind: sink, in: count, field: k8s.replicas, sensitivity: authoritative, rule: reps.ok, actor: "policy:x"}`

func FuzzGateBoundary(f *testing.F) {
	mustParse := func(src string) recipe.Parsed {
		p, err := recipe.Parse([]byte(src))
		if err != nil {
			f.Fatalf("recipe: %v", err)
		}
		return p
	}
	reroute := mustParse(rerouteSrc)
	replicas := mustParse(replicasSrc)

	rerouteTool := proxy.AdvertisedName("srv", "reroute")
	replicasTool := proxy.AdvertisedName("srv", "replicas")
	routes := proxy.Router{ // immutable, shared read-only across fuzz iterations
		rerouteTool:  {Recipe: reroute.Recipe, RecipeHash: reroute.SemanticHash, GateArg: "target", Server: "srv", Tool: "reroute"},
		replicasTool: {Recipe: replicas.Recipe, RecipeHash: replicas.SemanticHash, GateArg: "count", Server: "srv", Tool: "replicas"},
	}
	rerouteSet := map[string]bool{"eu-central": true, "us-east": true, "us-west": true}

	seeds := []struct {
		tool, args string
	}{
		{rerouteTool, `{"target":"eu-central"}`},          // benign, forwards
		{rerouteTool, `{"target":"attacker.evil"}`},       // out of set
		{rerouteTool, `{"target":" eu-central"}`},         // leading space
		{rerouteTool, `{"target":"eu-central "}`},         // trailing space
		{rerouteTool, `{"target":"EU-CENTRAL"}`},          // case
		{rerouteTool, `{"target":"eu-central\u0000"}`},    // null byte
		{rerouteTool, `{"target":"{{eu-central}}"}`},      // template markers
		{rerouteTool, `{"target":"eu-central","x":"1"}`},  // extra arg (coverage)
		{rerouteTool, `{"target":["eu-central","evil"]}`}, // array value
		{rerouteTool, `{"target":123}`},                   // wrong type
		{rerouteTool, `{}`},                               // missing arg
		{replicasTool, `{"count":"5"}`},                   // benign, forwards
		{replicasTool, `{"count":10}`},                    // benign boundary (inclusive max)
		{replicasTool, `{"count":"05"}`},                  // leading zero (non-canonical)
		{replicasTool, `{"count":"999"}`},                 // out of range
		{replicasTool, `{"count":11}`},                    // over-range integer
		{replicasTool, `{"count":"5 "}`},                  // trailing space
		{replicasTool, `{"count":"+5"}`},                  // signed
		{replicasTool, `{"count":"1e1"}`},                 // scientific-notation string
		{replicasTool, `{"count":7.5}`},                   // fractional number
		{replicasTool, `{"count":true}`},                  // boolean coercion
		{replicasTool, `{"count":5}`},                     // numeric type
		{"srv__wipe_database", `{"name":"prod-db"}`},      // unrouted destructive
		{"", `{}`},                   // empty tool
		{"srv__reroute", `not json`}, // malformed
	}
	for _, s := range seeds {
		f.Add(s.tool, []byte(s.args))
	}

	f.Fuzz(func(t *testing.T, tool string, argsJSON []byte) {
		cs := &countSink{}
		gate := proxy.Gate{Routes: routes, Sink: cs}
		dec := gate.Decide(context.Background(), proxy.ToolCall{Tool: tool, Raw: json.RawMessage(argsJSON)})

		// 1. Forward IFF Allow.
		if dec.Forward != (dec.Verdict == stag.Allow) {
			t.Fatalf("Forward=%v but Verdict=%v (Forward must mean Allow)", dec.Forward, dec.Verdict)
		}
		// 4. exactly one audit leaf.
		if cs.n != 1 {
			t.Fatalf("want exactly 1 audit leaf per decision, got %d", cs.n)
		}
		if !dec.Forward {
			return
		}
		// 2. only routed tools forward.
		if _, ok := routes[dec.Tool]; !ok {
			t.Fatalf("a NON-ROUTED tool forwarded: %q", dec.Tool)
		}
		// 3. the forwarded value is policy-compliant.
		switch dec.Tool {
		case rerouteTool:
			if !rerouteSet[dec.Value] {
				t.Fatalf("reroute forwarded an OUT-OF-SET target: %q (input=%s)", dec.Value, argsJSON)
			}
		case replicasTool:
			n, err := strconv.Atoi(dec.Value)
			if err != nil || n < 1 || n > 10 || strconv.Itoa(n) != dec.Value {
				t.Fatalf("replicas forwarded a NON-CANONICAL / out-of-range value: %q (input=%s)", dec.Value, argsJSON)
			}
		}
	})
}
