package proxy

import (
	"context"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// EPHEMERAL AUTHORIZATION. A recipe's `invoke` step MINTS a one-shot grant for exactly the call
// it authorized. The grant makes that call REACHABLE for one execution and is spent on use; the
// tool's own recipe still decides whether it is PERMITTED. Two grants, both required.
//
// This is the same primitive as a human approval — bound to a fingerprint, consumed on use,
// replay refused — with a deterministic minter instead of a person. The provenance must stay
// visible: nobody may later read a machine grant as though a human approved it.

// a minimal in-memory Authorizations for the tests
type memAuthz struct {
	live   map[string]Grant
	minted []Grant
	burned []string
}

func newMemAuthz() *memAuthz { return &memAuthz{live: map[string]Grant{}} }

func (m *memAuthz) Mint(_ context.Context, g Grant) error {
	m.live[g.Fingerprint] = g
	m.minted = append(m.minted, g)
	return nil
}
func (m *memAuthz) Lookup(_ context.Context, fp string) (Grant, bool, error) {
	g, ok := m.live[fp]
	return g, ok, nil
}
func (m *memAuthz) Burn(_ context.Context, fp string) error {
	delete(m.live, fp)
	m.burned = append(m.burned, fp)
	return nil
}

func labRecipe(t *testing.T) stag.Recipe {
	t.Helper()
	img := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"badport"}}
	return stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "image"},
		{Id: "s", Kind: stag.NodeSink, In: "image", Field: "lab.image",
			Sensitivity: stag.SinkAuthoritative, Rule: &img, RuleID: "image.this", Actor: "a"},
	}}
}

// An UNADVERTISED tool with no live grant is unreachable: the agent calling it directly is
// DENIED, not merely unlisted. Hiding is a convenience; this is the enforcement.
func TestUnadvertisedToolIsUnreachableWithoutAGrant(t *testing.T) {
	r := labRecipe(t)
	g := Gate{
		Routes: Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p",
			GateArg: "image", Sequenced: true}},
		Authorizations: newMemAuthz(),
	}
	d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: map[string]string{"image": "badport"}})
	if d.Forward {
		t.Fatal("an unadvertised tool with no live grant must not forward")
	}
	if d.Verdict != stag.Deny {
		t.Errorf("want deny, got %v", d.Verdict)
	}
}

// With a live grant for exactly this call, it is reachable — and the tool's OWN recipe still
// decides. A grant says WHEN, the recipe says WHAT.
func TestGrantMakesTheExactCallReachable(t *testing.T) {
	r := labRecipe(t)
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}
	fp := Fingerprint("lab__fix", args)
	_ = az.Mint(context.Background(), Grant{Fingerprint: fp, Tool: "lab__fix", Source: "policy:lab_repair_badport"})

	g := Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
	}
	d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args})
	if !d.Forward {
		t.Fatalf("a granted call whose recipe passes must forward: %+v", d)
	}
}

// The grant does NOT bypass the recipe. A granted call whose ARGUMENTS the tool's own policy
// refuses is still denied — this is what keeps a sequence from laundering an action.
func TestGrantDoesNotBypassTheRecipe(t *testing.T) {
	r := labRecipe(t) // only "badport" clears
	az := newMemAuthz()
	args := map[string]string{"image": "/etc/shadow"}
	_ = az.Mint(context.Background(), Grant{Fingerprint: Fingerprint("lab__fix", args), Tool: "lab__fix", Source: "policy:x"})

	g := Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
	}
	d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args})
	if d.Forward {
		t.Fatal("a grant must not make a policy-refused call permitted")
	}
}

// A grant is bound to the EXACT arguments. It cannot be redeemed for a different call on the
// same tool: an authorization for set_expose=8080 is not an authorization for set_user=root.
func TestGrantIsBoundToItsArguments(t *testing.T) {
	r := labRecipe(t)
	az := newMemAuthz()
	granted := map[string]string{"image": "badport"}
	_ = az.Mint(context.Background(), Grant{Fingerprint: Fingerprint("lab__fix", granted), Tool: "lab__fix", Source: "policy:x"})

	g := Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
	}
	// same tool, same rule-passing value, but a DIFFERENT argument set than was granted
	other := map[string]string{"image": "badport", "extra": "x"}
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: other}); d.Forward {
		t.Fatal("a grant must not cover a different argument set")
	}
}

// BURN ON USE. A forwarded call spends its grant; the identical call a second time is denied.
// This is what a routing flag cannot give: a hidden-but-routed tool can be called twice.
func TestGrantIsSpentOnUse(t *testing.T) {
	r := labRecipe(t)
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}
	fp := Fingerprint("lab__fix", args)
	_ = az.Mint(context.Background(), Grant{Fingerprint: fp, Tool: "lab__fix", Source: "policy:x"})

	g := Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
	}
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); !d.Forward {
		t.Fatal("first call must forward")
	}
	if len(az.burned) != 1 || az.burned[0] != fp {
		t.Errorf("the grant must be burned on use: %v", az.burned)
	}
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); d.Forward {
		t.Fatal("REPLAY: the identical call must be denied once the grant is spent")
	}
}

// A DENIED call does not burn its grant: the call never happened, so the authorization is
// still owed. (It expires with the sequence, not with a refusal.)
func TestDeniedCallDoesNotBurnTheGrant(t *testing.T) {
	r := labRecipe(t)
	az := newMemAuthz()
	args := map[string]string{"image": "/etc/shadow"} // recipe refuses this
	fp := Fingerprint("lab__fix", args)
	_ = az.Mint(context.Background(), Grant{Fingerprint: fp, Tool: "lab__fix", Source: "policy:x"})

	g := Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
	}
	g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args})
	if len(az.burned) != 0 {
		t.Errorf("a refused call must not spend the authorization: %v", az.burned)
	}
}

// An ORDINARY (non-sequenced) route is unaffected: it needs no grant, exactly as before.
// The zero value is the safe one, so every existing route keeps working.
func TestOrdinaryRouteNeedsNoGrant(t *testing.T) {
	r := labRecipe(t)
	g := Gate{
		Routes:         Router{"lab__read": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image"}},
		Authorizations: newMemAuthz(),
	}
	d := g.Decide(context.Background(), ToolCall{Tool: "lab__read", Args: map[string]string{"image": "badport"}})
	if !d.Forward {
		t.Errorf("an advertised route must not require a grant: %+v", d)
	}
}

// A gate with NO authorization store treats unadvertised routes as unreachable rather than
// open: absent machinery must fail closed, never fail open.
func TestNoAuthorizationStoreFailsClosed(t *testing.T) {
	r := labRecipe(t)
	g := Gate{Routes: Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p",
		GateArg: "image", Sequenced: true}}} // no Authorizations
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: map[string]string{"image": "badport"}}); d.Forward {
		t.Fatal("no authorization store must mean unreachable, not unguarded")
	}
}

// PROVENANCE. A machine-minted grant records the policy that minted it, so the audit can
// never read it as a human approval.
func TestGrantRecordsItsMinter(t *testing.T) {
	az := newMemAuthz()
	_ = az.Mint(context.Background(), Grant{Fingerprint: "fp", Tool: "t", Source: "policy:lab_repair_badport"})
	g, ok, _ := az.Lookup(context.Background(), "fp")
	if !ok || g.Source == "" {
		t.Fatal("a grant must name what minted it")
	}
	if g.Source == "human" {
		t.Error("a machine grant must not be indistinguishable from a human approval")
	}
}
