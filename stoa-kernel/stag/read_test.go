package stag

import "testing"

// READ — the recipe, not the model, decides what context is fetched and when.
//
// A context provider advertised as a tool leaves the ROUTING to the model: it picks which source
// to consult and writes the query itself. That is acceptable (a read is label+record, never
// denied, and the action is still gated) but it leaves the outbound query as free text, which is
// the READ-side of the leakage problem.
//
// A `read` step moves both decisions to the author. The provider is named in the recipe and the
// query comes from a gated slot, so the policy bounds what may be ASKED, not only what may be
// read back.
//
// It is NOT an invoke. A read is never denied, records no crossing, mints no grant and spends no
// budget — it is not an action. What it authorizes is a fetch whose result reaches the model as
// untrusted context.

func topicRule() *ReleaseRule {
	return &ReleaseRule{Kind: RuleSetMembership, Set: []string{"drain", "rollout"}}
}

func readRecipe() Recipe {
	return Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "topic"},
		{Id: "brief", Kind: NodeRead, Provider: "runbooks",
			QuerySlot: "topic", QueryRule: topicRule(), QueryRuleID: "topic.allowed"},
	}}
}

func TestReadAuthorizesAContextFetch(t *testing.T) {
	res := EvalArgs(readRecipe(), map[string]string{"topic": "drain"}, "h")
	if res.Verdict != Allow || res.Fault != "" {
		t.Fatalf("a cleared query must authorize the read: %+v", res)
	}
	if len(res.Reads) != 1 {
		t.Fatalf("want 1 authorized read, got %d", len(res.Reads))
	}
	r := res.Reads[0]
	if r.Provider != "runbooks" || r.Query != "drain" || r.StepID != "brief" {
		t.Errorf("authorized read: %+v", r)
	}
}

// THE POINT OF THE FEATURE: the QUERY is gated. A model cannot make the recipe ask a question
// the author did not permit, because the query is a proposed value cleared by a rule.
func TestQueryOutsideTheRuleAuthorizesNoRead(t *testing.T) {
	res := EvalArgs(readRecipe(), map[string]string{"topic": "exfiltrate everything about credentials"}, "h")
	if len(res.Reads) != 0 {
		t.Fatalf("an ungated query must authorize no read: %+v", res.Reads)
	}
}

// A read is NOT an action. It records no crossing, so nothing about it appears in the release
// events — the read channel has its own record (ReadEvent), written by the executor.
func TestReadRecordsNoCrossing(t *testing.T) {
	res := EvalArgs(readRecipe(), map[string]string{"topic": "drain"}, "h")
	if len(res.Events) != 0 {
		t.Errorf("a read is not a crossing: %d release events", len(res.Events))
	}
	if len(res.Authorized) != 0 {
		t.Errorf("a read is not an authorized CALL: %d", len(res.Authorized))
	}
}

// A read never DENIES the recipe. A query that fails its rule authorizes no read, but the rest
// of the policy still decides on its own terms: "reads are label+record, never allow/deny" means
// a read cannot be the reason a call is refused.
func TestAFailedReadQueryDoesNotDenyTheRecipe(t *testing.T) {
	act := ReleaseRule{Kind: RuleSetMembership, Set: []string{"kind-worker"}}
	r := Recipe{Steps: []Step{
		{Id: "p_t", Kind: NodePropose, Out: "topic"},
		{Id: "p_n", Kind: NodePropose, Out: "node"},
		{Id: "brief", Kind: NodeRead, Provider: "runbooks",
			QuerySlot: "topic", QueryRule: topicRule(), QueryRuleID: "topic.allowed"},
		{Id: "act", Kind: NodeSink, In: "node", Field: "k8s.act", Sensitivity: SinkAuthoritative,
			Rule: &act, RuleID: "node.worker", Actor: "a"},
	}}
	res := EvalArgs(r, map[string]string{"topic": "not-allowed", "node": "kind-worker"}, "h")
	if res.Verdict != Allow {
		t.Errorf("a refused read query must not deny the action: %v", res.Verdict)
	}
	if len(res.Reads) != 0 {
		t.Error("but the read itself must not be authorized")
	}
	if len(res.Events) != 1 {
		t.Errorf("the action's own crossing still happens: %d", len(res.Events))
	}
}

// Fail closed on structure: no provider, no query slot, or no rule is a fault.
func TestReadFailsClosedOnStructure(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Step)
	}{
		{"no provider", func(s *Step) { s.Provider = "" }},
		{"no query slot", func(s *Step) { s.QuerySlot = "" }},
		{"no query rule", func(s *Step) { s.QueryRule = nil }},
	}
	for _, c := range cases {
		r := readRecipe()
		c.mut(&r.Steps[1])
		res := EvalArgs(r, map[string]string{"topic": "drain"}, "h")
		if res.Fault == "" || res.Verdict != Deny {
			t.Errorf("%s: must fault, got %+v", c.name, res)
		}
		if len(res.Reads) != 0 {
			t.Errorf("%s: must authorize no read", c.name)
		}
	}
}

// A query slot nothing bound never clears.
func TestReadWithSeveredSlotAuthorizesNothing(t *testing.T) {
	r := readRecipe()
	r.Steps[1].QuerySlot = "nothing_bound_this"
	res := EvalArgs(r, map[string]string{"topic": "drain"}, "h")
	if len(res.Reads) != 0 {
		t.Errorf("severed slot: %+v", res.Reads)
	}
}

// Reads are authorized in source order, so a recipe can brief before it acts.
func TestReadsAreOrdered(t *testing.T) {
	r := Recipe{Steps: []Step{
		{Id: "p", Kind: NodePropose, Out: "topic"},
		{Id: "one", Kind: NodeRead, Provider: "runbooks", QuerySlot: "topic",
			QueryRule: topicRule(), QueryRuleID: "topic.allowed"},
		{Id: "two", Kind: NodeRead, Provider: "incidents", QuerySlot: "topic",
			QueryRule: topicRule(), QueryRuleID: "topic.allowed"},
	}}
	res := EvalArgs(r, map[string]string{"topic": "drain"}, "h")
	if len(res.Reads) != 2 {
		t.Fatalf("want 2 reads, got %d", len(res.Reads))
	}
	if res.Reads[0].Provider != "runbooks" || res.Reads[1].Provider != "incidents" {
		t.Errorf("source order not preserved: %+v", res.Reads)
	}
}

// A recipe that denies elsewhere still authorizes its reads: the read channel is independent of
// the verdict, because context is how an agent finds out WHY it was refused.
func TestReadsSurviveADeniedRecipe(t *testing.T) {
	never := ReleaseRule{Kind: RuleSetMembership, Set: []string{"__never__"}}
	r := Recipe{Steps: []Step{
		{Id: "p_t", Kind: NodePropose, Out: "topic"},
		{Id: "p_n", Kind: NodePropose, Out: "node"},
		{Id: "brief", Kind: NodeRead, Provider: "runbooks", QuerySlot: "topic",
			QueryRule: topicRule(), QueryRuleID: "topic.allowed"},
		{Id: "act", Kind: NodeSink, In: "node", Field: "f", Sensitivity: SinkAuthoritative,
			Rule: &never, RuleID: "never", Actor: "a"},
	}}
	res := EvalArgs(r, map[string]string{"topic": "drain", "node": "x"}, "h")
	if res.Verdict != Deny {
		t.Fatalf("the action must be denied: %v", res.Verdict)
	}
	if len(res.Reads) != 1 {
		t.Error("a denied action must not retract the reads: context explains the refusal")
	}
}

func TestNodeKindReadParse(t *testing.T) {
	k, err := ParseNodeKind("read")
	if err != nil || k != NodeRead || k.String() != "read" {
		t.Errorf("read node kind: k=%v err=%v str=%q", k, err, k.String())
	}
}
