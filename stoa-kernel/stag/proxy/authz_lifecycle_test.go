package proxy

import (
	"context"
	"sync"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// GRANT LIFECYCLE. A grant is runtime state with a lifetime, not configuration — so the
// questions that matter are about its WINDOW: who may spend it, how long it lives, and what
// happens when two sequences want the same one. None of these are reachable by editing a
// recipe, and all three are ways a one-shot authorization could quietly become a standing one.

func lifecycleGate(az Authorizations, session string) Gate {
	rule := stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"badport"}}
	r := stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "image"},
		{Id: "s", Kind: stag.NodeSink, In: "image", Field: "lab.image",
			Sensitivity: stag.SinkAuthoritative, Rule: &rule, RuleID: "image.this", Actor: "a"},
	}}
	return Gate{
		Routes:         Router{"lab__fix": {Recipe: r, RecipeHash: "h", RecipeName: "p", GateArg: "image", Sequenced: true}},
		Authorizations: az,
		Session:        session,
	}
}

// HOLE 1 — CROSS-SESSION. A grant minted while serving one bound session must not satisfy a
// call arriving on a DIFFERENT session. Sessions are the unit of authority in this product (a
// session is a grant, not a connection); an authorization that floats free of the session that
// minted it lets one agent spend another agent's permission.
func TestGrantIsNotSpendableByAnotherSession(t *testing.T) {
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}

	// session A's executor mints a grant for its own sequence
	gA := lifecycleGate(az, "session-A")
	_ = az.Mint(context.Background(), Grant{
		Fingerprint: Fingerprint("lab__fix", args), Tool: "lab__fix",
		Source: "policy:seq", Session: "session-A"})

	// session B — a different bound agent — makes the identical call
	gB := lifecycleGate(az, "session-B")
	if d := gB.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); d.Forward {
		t.Fatal("session B must not spend a grant minted for session A")
	}
	// and A's grant must still be intact: B's refusal may not consume it
	if d := gA.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); !d.Forward {
		t.Fatal("session A's own grant must survive another session's attempt")
	}
}

// HOLE 2 — CONCURRENCY. Two sequences racing on the same fingerprint must yield exactly ONE
// forward. A grant authorizes one call; if both win, a non-idempotent action (a restart, a
// drain) happens twice from a single authorization.
func TestConcurrentSequencesSpendAGrantOnce(t *testing.T) {
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}
	g := lifecycleGate(az, "s1")
	_ = az.Mint(context.Background(), Grant{
		Fingerprint: Fingerprint("lab__fix", args), Tool: "lab__fix", Source: "policy:seq", Session: "s1"})

	const n = 16
	var wg sync.WaitGroup
	forwards := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			forwards <- g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}).Forward
		}()
	}
	wg.Wait()
	close(forwards)
	got := 0
	for f := range forwards {
		if f {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("one grant must yield exactly one forward, got %d of %d", got, n)
	}
}

// HOLE 3 — LIFETIME. A grant must not outlive the sequence that minted it. If the executor
// dies between minting and calling, the grant persists in the store; on the next connection it
// would still be live, and a one-shot authorization has quietly become a standing one.
func TestGrantDoesNotOutliveItsSequence(t *testing.T) {
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}
	fp := Fingerprint("lab__fix", args)

	// a sequence mints a grant and then never uses it (the process died)
	_ = az.Mint(context.Background(), Grant{
		Fingerprint: fp, Tool: "lab__fix", Source: "policy:seq", Session: "s1", Run: "run-1"})

	// the sequence is over. Whatever ends it must have released the grant.
	if err := az.Sweep(context.Background(), "s1", "run-1"); err != nil {
		t.Fatal(err)
	}
	g := lifecycleGate(az, "s1")
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); d.Forward {
		t.Fatal("an abandoned grant must not still authorize a call")
	}
}

// A grant minted with NO session is not a wildcard: it must not satisfy a session-bound call.
// Fail closed on the ambiguous case rather than treating "unset" as "any".
func TestSessionlessGrantIsNotAWildcard(t *testing.T) {
	az := newMemAuthz()
	args := map[string]string{"image": "badport"}
	_ = az.Mint(context.Background(), Grant{
		Fingerprint: Fingerprint("lab__fix", args), Tool: "lab__fix", Source: "policy:seq"}) // no Session

	g := lifecycleGate(az, "session-A")
	if d := g.Decide(context.Background(), ToolCall{Tool: "lab__fix", Args: args}); d.Forward {
		t.Fatal("a grant with no session must not satisfy a session-bound call")
	}
}

// HOLE 4 — SWEEP IS TOO COARSE. Two sequences can share one session, so sweeping by session
// deletes a CONCURRENT sequence's outstanding grant mid-flight and halts it for no policy
// reason. A grant belongs to the RUN that minted it, not merely to the session.
func TestSweepDoesNotDisturbAConcurrentRun(t *testing.T) {
	az := newMemAuthz()
	ctx := context.Background()
	argsA := map[string]string{"image": "badport"}
	argsB := map[string]string{"image": "toolchain"}

	// two runs on the SAME session, each with an outstanding grant
	_ = az.Mint(ctx, Grant{Fingerprint: Fingerprint("lab__fix", argsA), Tool: "lab__fix",
		Source: "policy:seq", Session: "s1", Run: "run-A"})
	_ = az.Mint(ctx, Grant{Fingerprint: Fingerprint("lab__fix", argsB), Tool: "lab__fix",
		Source: "policy:seq", Session: "s1", Run: "run-B"})

	// run A finishes and sweeps ITS OWN grants
	if err := az.Sweep(ctx, "s1", "run-A"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := az.Redeem(ctx, Fingerprint("lab__fix", argsA), "s1"); ok {
		t.Error("run A's own grant must be swept")
	}
	if _, ok, _ := az.Redeem(ctx, Fingerprint("lab__fix", argsB), "s1"); !ok {
		t.Fatal("run B's grant must survive run A's sweep: they share a session, not a run")
	}
}
