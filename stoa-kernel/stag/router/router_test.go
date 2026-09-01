package router_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/router"
)

func policy(name, tool, arg string) string {
	return fmt.Sprintf(`recipe: %s
version: 1
rules:
  r.allowed:
    kind: set_membership
    set: ["ok"]
steps:
  - id: p
    kind: propose
    out: v
  - id: s
    kind: sink
    in: v
    field: mcp.%s.%s
    sensitivity: authoritative
    rule: r.allowed
    actor: "policy:x"
`, name, tool, arg)
}

// passthroughPolicy is a VALID recipe that declares a free-text passthrough field — so its leakage is
// UNBOUNDED (a free-text argument reaches an external sink). Legitimate (notify's message, ticket's
// summary), but it voids the per-session leakage bound for that route.
func passthroughPolicy(name, tool, arg string) string {
	return fmt.Sprintf(`recipe: %s
version: 1
passthrough: ["free"]
rules:
  r.allowed:
    kind: set_membership
    set: ["ok"]
steps:
  - id: p
    kind: propose
    out: v
  - id: s
    kind: sink
    in: v
    field: mcp.%s.%s
    sensitivity: authoritative
    rule: r.allowed
    actor: "policy:x"
`, name, tool, arg)
}

func loaderFrom(m map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if src, ok := m[name]; ok {
			return []byte(src), nil
		}
		return nil, fmt.Errorf("recipe %q not found", name)
	}
}

func TestBuildValid(t *testing.T) {
	load := loaderFrom(map[string]string{
		"policyA": policy("policya", "write_note", "text"),
		"policyB": policy("policyb", "scale", "n"),
	})
	res := router.Build([]router.Spec{
		{Tool: "write_note", Server: "srv", Recipe: "policyA", GateArg: "text"},
		{Tool: "scale", Server: "srv", Recipe: "policyB", GateArg: "n"},
	}, load)
	if len(res.Router) != 2 || len(res.Errors) != 0 {
		t.Fatalf("want 2 routes, 0 errors: %d routes, %+v errors", len(res.Router), res.Errors)
	}
	// the Router is keyed by the ADVERTISED name; Route.Tool keeps the downstream's own name.
	rt := res.Router[proxy.AdvertisedName("srv", "write_note")]
	if rt.GateArg != "text" || rt.RecipeHash == "" || rt.Tool != "write_note" || rt.Server != "srv" {
		t.Errorf("resolved route: %+v", rt)
	}
}

func TestBuildFailsClosed(t *testing.T) {
	load := loaderFrom(map[string]string{
		"good":    policy("good", "write_note", "text"),
		"garbage": "this: is: not: a recipe {{{",
	})
	res := router.Build([]router.Spec{
		{Tool: "write_note", Server: "srv", Recipe: "good", GateArg: "text"},
		{Tool: "missing_tool", Server: "srv", Recipe: "absent", GateArg: "x"}, // loader errors
		{Tool: "bad_tool", Server: "srv", Recipe: "garbage", GateArg: "x"},    // parse errors
	}, load)

	if len(res.Router) != 1 {
		t.Fatalf("only the valid tool routes: %d", len(res.Router))
	}
	if _, ok := res.Router[proxy.AdvertisedName("srv", "write_note")]; !ok {
		t.Error("valid tool must survive alongside bad ones")
	}
	if _, ok := res.Router[proxy.AdvertisedName("srv", "missing_tool")]; ok {
		t.Error("missing recipe must not route (fail closed)")
	}
	if _, ok := res.Router[proxy.AdvertisedName("srv", "bad_tool")]; ok {
		t.Error("invalid recipe must not route (fail closed)")
	}
	if len(res.Errors) != 2 {
		t.Errorf("both failures reported: %+v", res.Errors)
	}
}

// BuildStrict(requireBounded) is the advertise-time leakage gate (Planning/34 §6.1). A recipe with
// unbounded leakage (a free-text passthrough) binds-with-a-warning in the default mode, but is REFUSED
// — no router entry, an error, tool left unrouted, gate denies — in strict mode. A bounded recipe binds
// clean either way. Passthrough is a legitimate, declared choice, so the default must not break it.
func TestBuildStrictGatesUnbounded(t *testing.T) {
	load := loaderFrom(map[string]string{
		"bounded":   policy("bounded", "reroute", "target"),
		"unbounded": passthroughPolicy("unbounded", "notify", "channel"),
	})
	specs := []router.Spec{
		{Tool: "reroute", Server: "srv", Recipe: "bounded", GateArg: "target"},
		{Tool: "notify", Server: "srv", Recipe: "unbounded", GateArg: "channel"},
	}
	bounded := proxy.AdvertisedName("srv", "reroute")
	unbounded := proxy.AdvertisedName("srv", "notify")

	// default (non-strict): both bind; the unbounded one is a WARNING, not an error.
	def := router.Build(specs, load)
	if len(def.Router) != 2 {
		t.Fatalf("default mode binds both routes: got %d", len(def.Router))
	}
	if len(def.Warnings) != 1 || len(def.Errors) != 0 {
		t.Fatalf("the unbounded route must WARN (not error) by default: warns=%+v errs=%+v", def.Warnings, def.Errors)
	}

	// strict: the unbounded route is REFUSED; the bounded one survives.
	strict := router.BuildStrict(specs, load, true)
	if _, ok := strict.Router[unbounded]; ok {
		t.Error("strict mode must REFUSE the unbounded route (no router entry -> gate denies)")
	}
	if _, ok := strict.Router[bounded]; !ok {
		t.Error("the bounded route must still bind under strict mode")
	}
	if len(strict.Errors) != 1 || len(strict.Warnings) != 0 {
		t.Fatalf("strict: the unbounded route becomes an ERROR, not a warning: errs=%+v warns=%+v", strict.Errors, strict.Warnings)
	}
}

// A route whose gate-arg covers an argument the recipe never CONSTRAINS forwards it as free-text, even
// though the recipe alone reports bounded (adversarial finding: boundedness is a property of the
// (recipe, gateArg) pair, not the recipe). The recipe below constrains only `channel`; the route also
// gates `message`, which no rule bounds — the same free-text hole as `passthrough:[message]`, so strict
// mode must refuse it and default mode must warn.
func TestBuildStrictCatchesUnconstrainedGateArg(t *testing.T) {
	load := loaderFrom(map[string]string{
		"notifyish": `recipe: notifyish
version: 1
rules:
  ch.ok: {kind: set_membership, set: ["ops", "sec"]}
steps:
  - {id: p, kind: propose, out: channel}
  - {id: s, kind: sink, in: channel, field: mcp.notify.channel, sensitivity: authoritative, rule: ch.ok, actor: "policy:x"}`,
	})
	specs := []router.Spec{{Tool: "notify", Server: "srv", Recipe: "notifyish", GateArg: "channel,message"}}
	adv := proxy.AdvertisedName("srv", "notify")

	def := router.Build(specs, load)
	if _, ok := def.Router[adv]; !ok || len(def.Warnings) != 1 {
		t.Fatalf("default mode binds with a free-text warning: router=%d warns=%+v", len(def.Router), def.Warnings)
	}
	strict := router.BuildStrict(specs, load, true)
	if _, ok := strict.Router[adv]; ok {
		t.Error("strict mode must REFUSE a route with an unconstrained (free-text) gate-arg slot")
	}
	if len(strict.Errors) != 1 {
		t.Fatalf("the unconstrained gate-arg must be an error in strict mode: %+v", strict.Errors)
	}
}

func FuzzBuild(f *testing.F) {
	f.Add([]byte(policy("p", "t", "a")))
	f.Add([]byte(""))
	f.Add([]byte("garbage {{{ not yaml"))
	f.Fuzz(func(t *testing.T, src []byte) {
		load := func(name string) ([]byte, error) {
			if name == "r" {
				return src, nil
			}
			return nil, fmt.Errorf("no %q", name)
		}
		specs := []router.Spec{{Tool: "t", Server: "srv", Recipe: "r", GateArg: "a"}}
		res := router.Build(specs, load)

		_, routed := res.Router[proxy.AdvertisedName("srv", "t")]
		errored := false
		for _, e := range res.Errors {
			if e.Tool == "t" {
				errored = true
			}
		}
		if routed == errored {
			t.Fatalf("exactly one of routed/errored must hold: routed=%v errored=%v", routed, errored)
		}

		_, perr := recipe.Parse(src)
		if routed {
			if perr != nil {
				t.Fatalf("routed but recipe does not parse: %v", perr)
			}
			if rt := res.Router[proxy.AdvertisedName("srv", "t")]; rt.GateArg != "a" || rt.Tool != "t" {
				t.Fatalf("gate arg or downstream tool name lost: %+v", rt)
			}
		} else if perr == nil {
			t.Fatalf("errored but recipe parses fine")
		}

		if res2 := router.Build(specs, load); !reflect.DeepEqual(res, res2) {
			t.Fatalf("nondeterministic")
		}
	})
}
