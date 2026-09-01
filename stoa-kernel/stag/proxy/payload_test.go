package proxy_test

// kw-test: the gate judges the PAYLOAD, not just the scalars around it — every element of an array must
// clear, a composite path is denied rather than stringified, and a zero-arg tool is authorized by its route

import (
	"context"
	"encoding/json"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// A push_files-shaped policy: only files under src/ may be written. The interesting part of the call is
// the PAYLOAD (`files`), which the old fmt.Sprint reader could not judge at all.
const pathPolicy = `recipe: push_policy
version: 1
rules:
  path.allowed:
    kind: set_membership
    set: ["src/a.go", "src/b.go"]
steps:
  - id: propose_path
    kind: propose
    out: path
  - id: write
    kind: sink
    in: path
    field: mcp.push_files.path
    sensitivity: authoritative
    rule: path.allowed
    actor: "policy:mcp_proxy"
`

// A tool with NO arguments: the ROUTE is the authorization. The recipe still runs, and a benign sink
// clears it — that is what makes a zero-argument tool like GitHub's get_me routable at all.
const zeroArgPolicy = `recipe: permit_read
version: 1
steps:
  - id: propose_nothing
    kind: propose
    out: v
  - id: read
    kind: sink
    in: v
    field: mcp.get_me
    sensitivity: benign
`

func gateFor(t *testing.T, src, gateArg string) proxy.Gate {
	t.Helper()
	p, err := recipe.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return proxy.Gate{Routes: proxy.Router{
		"srv__tool": {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: gateArg, Server: "srv", Tool: "tool"},
	}}
}

func call(raw string) proxy.ToolCall {
	return proxy.ToolCall{Tool: "srv__tool", Raw: json.RawMessage(raw)}
}

// EVERY element of the array is judged. An array must not be a way to smuggle one disallowed value past
// a rule that the other elements happen to satisfy.
func TestArrayPayloadEveryElementMustClear(t *testing.T) {
	g := gateFor(t, pathPolicy, "files[].path")
	ctx := context.Background()

	// all elements allowed -> forward
	ok := g.Decide(ctx, call(`{"files":[{"path":"src/a.go"},{"path":"src/b.go"}]}`))
	if ok.Verdict != stag.Allow || !ok.Forward {
		t.Fatalf("every element allowed must forward: %+v", ok)
	}

	// ONE bad element among good ones -> DENY the whole call. This is the property that matters: the
	// good elements do not launder the bad one.
	bad := g.Decide(ctx, call(`{"files":[{"path":"src/a.go"},{"path":"../../etc/passwd"}]}`))
	if bad.Verdict != stag.Deny || bad.Forward {
		t.Fatalf("one disallowed element must deny the whole call: %+v", bad)
	}

	// and the bad path is visible in the audit value — the record says what was actually judged
	if bad.Value == "" {
		t.Error("the audit value must show the values the gate judged")
	}
}

// A path that lands on a composite is DENIED, not stringified. The old reader answered
// "[map[content:... path:...]]" and let a rule compare against Go's memory syntax.
func TestCompositePathDenies(t *testing.T) {
	ctx := context.Background()
	for _, gateArg := range []string{"files", "files[]"} {
		d := gateFor(t, pathPolicy, gateArg).Decide(ctx, call(`{"files":[{"path":"src/a.go"}]}`))
		if d.Verdict != stag.Deny || d.Forward {
			t.Errorf("gateArg %q lands on a composite and must DENY, got %+v", gateArg, d)
		}
		if d.Fault == "" {
			t.Errorf("gateArg %q: a denial for an unjudgeable path must say why", gateArg)
		}
	}
}

// A zero-argument tool is authorized by its route: the recipe runs with an empty proposal and a benign
// sink clears it. Without this, a tool like get_me could not be routed at all, so the agent could never
// call it.
func TestZeroArgToolIsRoutableAndAllowed(t *testing.T) {
	d := gateFor(t, zeroArgPolicy, "").Decide(context.Background(), call(`{}`))
	if d.Verdict != stag.Allow || !d.Forward {
		t.Fatalf("a zero-arg tool on a permitting recipe must forward: %+v", d)
	}
}

// The gate judges the value that will actually SHIP. A JSON number 3 is judged as "3" (not Go's
// "3e+00"), so an allow-set a human wrote matches the payload a downstream receives.
func TestScalarsAreCanonical(t *testing.T) {
	const numPolicy = `recipe: scale_policy
version: 1
rules:
  scale.allowed:
    kind: set_membership
    set: ["3"]
steps:
  - id: p
    kind: propose
    out: replicas
  - id: s
    kind: sink
    in: replicas
    field: mcp.scale.replicas
    sensitivity: authoritative
    rule: scale.allowed
    actor: "policy:mcp_proxy"
`
	d := gateFor(t, numPolicy, "replicas").Decide(context.Background(), call(`{"replicas":3}`))
	if d.Verdict != stag.Allow {
		t.Fatalf("JSON number 3 must be judged as \"3\" and match the allow-set: %+v", d)
	}
}
