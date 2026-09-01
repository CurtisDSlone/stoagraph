package stag

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
)

const rh = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func byteAt(s []byte, i int) byte {
	if len(s) == 0 {
		return 0
	}
	return s[i%len(s)]
}

// fixture: Planning/09 cdn_remediation in struct form.
// branch rule (routes.all) is deliberately broader than the gate/sink rule so
// the escalate path is reachable.
func fixture(escalate bool) Recipe {
	routesAll := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"class:regional_fallback", "class:edge_only", "class:transcontinental"}}
	routesAuto := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"class:regional_fallback", "class:edge_only"}}
	cacheApproved := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"class:release_prewarm"}}
	return Recipe{Steps: []Step{
		{Id: "propose_plan", Kind: NodePropose, Out: "plan"},
		{Id: "choose_path", Kind: NodeBranch, In: "plan",
			Cases:   []Case{{Rule: routesAll, Goto: "check_route"}, {Rule: cacheApproved, Goto: "apply_prefetch"}},
			Default: "log_only"},
		{Id: "check_route", Kind: NodeGate, In: "plan", Rule: routesAuto, Escalate: escalate},
		{Id: "apply_route", Kind: NodeSink, In: "plan", Sensitivity: SinkAuthoritative,
			Rule: routesAuto, RuleID: "routes.auto_approvable", Field: "aws_route_apply.args.route",
			Actor: "policy:network_remediation", Goto: "log_only"},
		{Id: "apply_prefetch", Kind: NodeSink, In: "plan", Sensitivity: SinkAuthoritative,
			Rule: cacheApproved, RuleID: "cache.approved", Field: "edge_cache_prefetch.args.plan",
			Actor: "policy:cache_budget"},
		{Id: "log_only", Kind: NodeSink, In: "plan", Sensitivity: SinkBenign, Field: "log.plan"},
	}}
}

func TestRecipeEval(t *testing.T) {
	fx := fixture(true)

	// path 1: auto-allow route (branch -> gate pass -> auth sink -> goto log)
	r1 := Eval(fx, "class:regional_fallback", rh)
	if r1.Verdict != Allow || r1.Fault != "" {
		t.Errorf("path1: verdict=%v fault=%q, want Allow,\"\"", r1.Verdict, r1.Fault)
	}
	if len(r1.Events) != 1 {
		t.Fatalf("path1: events=%d, want 1", len(r1.Events))
	}
	e := r1.Events[0]
	if e.TargetField != "aws_route_apply.args.route" || e.AuthorizingRule != "routes.auto_approvable" ||
		e.RecipeHash != rh || e.Ordering != 3 || e.SubjectClass != Untrusted {
		t.Errorf("path1: event fields wrong: %+v", e)
	}
	if len(r1.Gates) != 1 || !r1.Gates[0].Passed || r1.Gates[0].Verdict != Allow || r1.Gates[0].Id != "check_route" {
		t.Errorf("path1: gates wrong: %+v", r1.Gates)
	}
	if len(r1.Sinks) != 2 || r1.Sinks[0].Field != "aws_route_apply.args.route" || r1.Sinks[1].Field != "log.plan" {
		t.Errorf("path1: sinks wrong (want auth then log, prefetch not taken): %+v", r1.Sinks)
	}

	// path 2: prefetch-allow (branch routes past the gate)
	r2 := Eval(fx, "class:release_prewarm", rh)
	if r2.Verdict != Allow || r2.Fault != "" || len(r2.Gates) != 0 {
		t.Errorf("path2: verdict=%v fault=%q gates=%d, want Allow,\"\",0", r2.Verdict, r2.Fault, len(r2.Gates))
	}
	if len(r2.Events) != 1 || r2.Events[0].TargetField != "edge_cache_prefetch.args.plan" || r2.Events[0].Ordering != 4 {
		t.Errorf("path2: events wrong: %+v", r2.Events)
	}
	if len(r2.Sinks) != 2 || r2.Sinks[1].Field != "log.plan" {
		t.Errorf("path2: sinks wrong (want prefetch then fall-through log): %+v", r2.Sinks)
	}

	// path 3: escalate (gate fails on a present value with escalate declared; walk halts)
	r3 := Eval(fx, "class:transcontinental", rh)
	if r3.Verdict != Escalate || r3.Fault != "" {
		t.Errorf("path3: verdict=%v fault=%q, want Escalate,\"\"", r3.Verdict, r3.Fault)
	}
	if len(r3.Events) != 0 || len(r3.Sinks) != 0 {
		t.Errorf("path3: events=%d sinks=%d, want 0,0 (actuator never reached)", len(r3.Events), len(r3.Sinks))
	}
	if len(r3.Gates) != 1 || r3.Gates[0].Passed || r3.Gates[0].Verdict != Escalate {
		t.Errorf("path3: gates wrong: %+v", r3.Gates)
	}

	// path 4: spoof-inert (default routes to the benign log; nothing authoritative reached)
	r4 := Eval(fx, "rm -rf /", rh)
	if r4.Verdict != Allow || len(r4.Events) != 0 || len(r4.Gates) != 0 ||
		len(r4.Sinks) != 1 || r4.Sinks[0].Sink != SinkBenign {
		t.Errorf("path4: %+v", r4)
	}

	// gate defaults to Deny when escalate is not declared
	rd := Eval(fixture(false), "class:transcontinental", rh)
	if rd.Verdict != Deny || len(rd.Gates) != 1 || rd.Gates[0].Verdict != Deny || len(rd.Sinks) != 0 {
		t.Errorf("gate default deny: %+v", rd)
	}

	// escalate never softens uncertainty: severed input and nil rule both Deny
	sev := Eval(Recipe{Steps: []Step{
		{Id: "g", Kind: NodeGate, In: "nope", Rule: &ReleaseRule{Kind: RuleSetMembership, Set: []string{"x"}}, Escalate: true},
	}}, "", rh)
	if sev.Verdict != Deny || len(sev.Gates) != 1 || sev.Gates[0].Verdict != Deny || sev.Fault != "" {
		t.Errorf("gate severed: %+v", sev)
	}
	nr := Eval(Recipe{
		Ingredients: map[string]Slot{"x": {Value: "v", Class: Untrusted}},
		Steps:       []Step{{Id: "g", Kind: NodeGate, In: "x", Escalate: true}},
	}, "", rh)
	if nr.Verdict != Deny || len(nr.Gates) != 1 || nr.Gates[0].Verdict != Deny {
		t.Errorf("gate nil rule: %+v", nr)
	}

	// faults fail closed: unknown goto, backward goto, branch severed, branch no-match
	// with empty default, unknown kind
	faults := []Recipe{
		{Steps: []Step{{Id: "p", Kind: NodePropose, Out: "o", Goto: "nowhere"},
			{Id: "s", Kind: NodeSink, In: "o", Sensitivity: SinkBenign, Field: "f"}}},
		{Steps: []Step{{Id: "a", Kind: NodePropose, Out: "o"},
			{Id: "b", Kind: NodeSink, In: "o", Sensitivity: SinkBenign, Field: "f", Goto: "a"}}},
		{Steps: []Step{{Id: "br", Kind: NodeBranch, In: "nope",
			Cases: []Case{{Rule: &ReleaseRule{Kind: RuleSetMembership, Set: []string{"x"}}, Goto: "z"}}, Default: "z"},
			{Id: "z", Kind: NodeSink, In: "nope", Sensitivity: SinkBenign, Field: "f"}}},
		{Steps: []Step{{Id: "p", Kind: NodePropose, Out: "o"},
			{Id: "br", Kind: NodeBranch, In: "o",
				Cases: []Case{{Rule: &ReleaseRule{Kind: RuleSetMembership, Set: []string{"never"}}, Goto: "z"}}},
			{Id: "z", Kind: NodeSink, In: "o", Sensitivity: SinkBenign, Field: "f"}}},
		{Steps: []Step{{Id: "j", Kind: NodeKind(9)},
			{Id: "s", Kind: NodeSink, In: "o", Sensitivity: SinkBenign, Field: "f"}}},
	}
	for i, fr := range faults {
		res := Eval(fr, "v", rh)
		if res.Fault == "" || res.Verdict != Deny {
			t.Errorf("fault[%d]: fault=%q verdict=%v, want non-empty,Deny (%+v)", i, res.Fault, res.Verdict, res)
		}
	}

	// a missing slot NEVER releases, even against a rule enumerating "" (U7 v2 adversarial finding)
	ms := Eval(Recipe{Steps: []Step{
		{Id: "s", Kind: NodeSink, In: "absent", Sensitivity: SinkAuthoritative,
			Rule: &ReleaseRule{Kind: RuleSetMembership, Set: []string{""}}, RuleID: "r", Field: "f", Actor: "a"},
	}}, "anything", rh)
	if ms.Verdict != Deny || len(ms.Events) != 0 || ms.Sinks[0].Released {
		t.Errorf("severed slot released against empty-string set: %+v", ms)
	}

	// a sink Deny refuses the crossing, not the movement
	sd := Eval(Recipe{
		Ingredients: map[string]Slot{"u": {Value: "bad", Class: Untrusted}},
		Steps: []Step{
			{Id: "a", Kind: NodeSink, In: "u", Sensitivity: SinkAuthoritative, Field: "f1"},
			{Id: "b", Kind: NodeSink, In: "u", Sensitivity: SinkBenign, Field: "f2"},
		},
	}, "", rh)
	if sd.Verdict != Deny || len(sd.Sinks) != 2 || sd.Sinks[0].Verdict != Deny || sd.Sinks[1].Verdict != Allow ||
		len(sd.Events) != 0 || sd.Fault != "" {
		t.Errorf("sink deny continues: %+v", sd)
	}

	// v1 back-compat: linear recipes evaluate as before (3-arg)
	setRule := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"restart", "isolate", "notify"}}
	lin := Recipe{Steps: []Step{
		{Kind: NodePropose, Out: "action"},
		{Kind: NodeSink, In: "action", Sensitivity: SinkAuthoritative, Rule: setRule, RuleID: "actions.approved", Field: "act.args.action", Actor: "policy:remediation"},
	}}
	h1 := Eval(lin, "restart", rh)
	if h1.Verdict != Allow || len(h1.Events) != 1 || h1.Events[0].RecipeHash != rh || h1.Events[0].Ordering != 1 {
		t.Errorf("compat happy: %+v", h1)
	}
	if d := Eval(lin, "rm -rf /", rh); d.Verdict != Deny || len(d.Events) != 0 {
		t.Errorf("compat denied: %+v", d)
	}
	if a := Eval(Recipe{
		Ingredients: map[string]Slot{"fact": {Value: "x", Class: Authoritative, Origin: "pip"}},
		Steps:       []Step{{Kind: NodeSink, In: "fact", Sensitivity: SinkAuthoritative, Field: "f"}},
	}, "", rh); a.Verdict != Allow || len(a.Events) != 0 {
		t.Errorf("compat auth subject: %+v", a)
	}
	if b := Eval(Recipe{
		Ingredients: map[string]Slot{"x": {Value: "anything", Class: Untrusted}},
		Steps:       []Step{{Kind: NodeSink, In: "x", Sensitivity: SinkBenign, Field: "log"}},
	}, "", rh); b.Verdict != Allow || len(b.Events) != 0 {
		t.Errorf("compat benign: %+v", b)
	}
	if m := Eval(Recipe{Steps: []Step{{Kind: NodeSink, In: "nope", Sensitivity: SinkAuthoritative, Field: "f"}}}, "", rh); m.Verdict != Deny || len(m.Events) != 0 {
		t.Errorf("compat missing slot: %+v", m)
	}
	if r := Eval(Recipe{
		Ingredients: map[string]Slot{"u": {Value: "restart", Class: Untrusted}, "u2": {Value: "bad", Class: Untrusted}},
		Steps: []Step{
			{Kind: NodeSink, In: "u", Sensitivity: SinkAuthoritative, Rule: setRule, Field: "a"},
			{Kind: NodeSink, In: "u2", Sensitivity: SinkAuthoritative, Rule: setRule, Field: "b"},
		},
	}, "", rh); r.Verdict != Deny {
		t.Errorf("compat rollup: %+v", r)
	}
	if Eval(Recipe{}, "", rh).Verdict != Allow {
		t.Errorf("compat empty recipe should be Allow")
	}

	// recipe hash threading: "" permitted; differing hashes yield differing event hashes
	z := Eval(lin, "restart", "")
	if len(z.Events) != 1 || z.Events[0].RecipeHash != "" {
		t.Errorf("rh empty: %+v", z.Events)
	}
	za, _ := z.Events[0].Hash()
	zb, _ := h1.Events[0].Hash()
	if za == zb {
		t.Errorf("rh threading: event hashes should differ across recipe hashes")
	}

	// nodekind register: canonical spellings + fail-closed parse
	wantStr := map[NodeKind]string{NodePropose: "propose", NodeSink: "sink", NodeBranch: "branch", NodeGate: "gate", NodeForeach: "foreach", NodeExit: "exit", NodeKind(99): "unknown"}
	for k, w := range wantStr {
		if k.String() != w {
			t.Errorf("NodeKind(%d).String()=%q, want %q", int(k), k.String(), w)
		}
	}
	for _, k := range []NodeKind{NodePropose, NodeSink, NodeBranch, NodeGate, NodeForeach, NodeExit} {
		if got, err := ParseNodeKind(k.String()); err != nil || got != k {
			t.Errorf("round-trip: ParseNodeKind(%q)=%v,%v", k.String(), got, err)
		}
	}
	for _, s := range []string{"unknown", "", "Propose", " gate "} {
		if got, err := ParseNodeKind(s); err == nil || got != NodeKind(-1) {
			t.Errorf("fail-closed: ParseNodeKind(%q)=%v,%v, want -1,error", s, got, err)
		}
	}

	// events are valid records; determinism
	for _, ev := range r1.Events {
		if h, err := ev.Hash(); err != nil || len(h) != 64 {
			t.Errorf("event hash invalid: %q %v", h, err)
		}
	}
	if da, db := Eval(fx, "class:regional_fallback", rh), Eval(fx, "class:regional_fallback", rh); !reflect.DeepEqual(da, db) {
		t.Errorf("determinism: results differ")
	}
}

func FuzzRecipeEval(f *testing.F) {
	f.Add("class:regional_fallback", []byte{0, 1, 2, 3, 0, 1})
	f.Add("class:release_prewarm", []byte{2, 2, 1, 0})
	f.Add("class:transcontinental", []byte{1, 3, 2, 4})
	f.Add("rm -rf /", []byte{})
	f.Fuzz(func(t *testing.T, proposal string, shape []byte) {
		setRule := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"restart", "isolate", "notify", "class:regional_fallback"}}
		numRule := &ReleaseRule{Kind: RuleNumericRange, Min: 1, Max: 10}
		emptyRule := &ReleaseRule{Kind: RuleSetMembership, Set: []string{"", "restart"}} // "" enumerated: missing slots must still never release
		rulePool := []*ReleaseRule{setRule, numRule, emptyRule, nil}

		ingredients := map[string]Slot{}
		vals := []string{proposal, "restart", "5", "bad"}
		for i := 0; i < 3; i++ {
			ingredients[fmt.Sprintf("ing%d", i)] = Slot{Value: vals[i%len(vals)], Class: TrustClass(byteAt(shape, i) % 4), Origin: "ing"}
		}

		nSteps := 1 + int(byteAt(shape, 5)%8)
		ids := make([]string, nSteps)
		for j := range ids {
			ids[j] = fmt.Sprintf("s%d", j)
		}
		slotPool := []string{"ing0", "ing1", "ing2", "out0", "out1", "missing"}
		// edge pool per step: fall-through, valid forward, dangling, backward/self
		pickGoto := func(j int, b byte) string {
			switch b % 4 {
			case 0:
				return ""
			case 1:
				if j+1 < nSteps {
					return ids[j+1+int(byteAt(shape, 60+j))%(nSteps-j-1)]
				}
				return ""
			case 2:
				return "dangling"
			default:
				return ids[int(byteAt(shape, 70+j))%(j+1)] // backward or self
			}
		}

		steps := make([]Step, nSteps)
		for j := 0; j < nSteps; j++ {
			kind := byteAt(shape, 10+j) % 5
			st := Step{Id: ids[j], Goto: pickGoto(j, byteAt(shape, 20+j))}
			switch kind {
			case 0:
				st.Kind = NodePropose
				st.Out = fmt.Sprintf("out%d", j%2)
			case 1:
				st.Kind = NodeSink
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				st.Sensitivity = SinkSensitivity(byteAt(shape, 40+j) % 3)
				st.Rule = rulePool[int(byteAt(shape, 50+j))%len(rulePool)]
				st.RuleID = "r"
				st.Field = fmt.Sprintf("f%d", j)
				st.Actor = "a"
			case 2:
				st.Kind = NodeBranch
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				nc := int(byteAt(shape, 80+j) % 3)
				for c := 0; c < nc; c++ {
					st.Cases = append(st.Cases, Case{Rule: rulePool[int(byteAt(shape, 90+j+c))%len(rulePool)], Goto: pickGoto(j, byteAt(shape, 100+j+c))})
				}
				if byteAt(shape, 110+j)%2 == 0 {
					st.Default = pickGoto(j, byteAt(shape, 120+j))
				}
				st.Goto = ""
			case 3:
				st.Kind = NodeGate
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				st.Rule = rulePool[int(byteAt(shape, 50+j))%len(rulePool)]
				st.Escalate = byteAt(shape, 130+j)%2 == 1
			default:
				st.Kind = NodeKind(7) // junk kind: must Fault, never skip
			}
			steps[j] = st
		}

		recipe := Recipe{Ingredients: ingredients, Steps: steps}
		res := Eval(recipe, proposal, rh)

		// (1) THE INVARIANT: Allow at an authoritative sink for a non-authoritative
		// subject => a recorded ReleaseEvent bound to the recipe hash.
		for _, o := range res.Sinks {
			if o.Verdict == Allow && o.Sink == SinkAuthoritative && o.Subject != Authoritative {
				found := false
				for _, ev := range res.Events {
					if ev.TargetField == o.Field && ev.RecipeHash == rh {
						found = true
					}
				}
				if !found {
					t.Errorf("FAIL-OPEN: Allow crossing at %q (subject %v) has no bound ReleaseEvent", o.Field, o.Subject)
				}
			}
		}
		// (2) CONVERSE: no spurious events; and events are COUNT-bijective with cleared
		// crossings (closes the field-aliasing gap in the pairwise checks).
		for _, ev := range res.Events {
			ok := false
			for _, o := range res.Sinks {
				if o.Field == ev.TargetField && o.Sink == SinkAuthoritative && o.Subject != Authoritative && o.Released && o.Verdict == Allow {
					ok = true
				}
			}
			if !ok {
				t.Errorf("SPURIOUS event for field %q with no matching cleared crossing", ev.TargetField)
			}
		}
		cleared := 0
		for _, o := range res.Sinks {
			if o.Sink == SinkAuthoritative && o.Subject != Authoritative && o.Released && o.Verdict == Allow {
				cleared++
			}
		}
		if len(res.Events) != cleared {
			t.Errorf("BIJECTION: %d events for %d cleared crossings", len(res.Events), cleared)
		}
		// (3) ROLLUP LAW: verdict == AndAll(gates, sinks, fault-deny).
		var vs []Verdict
		for _, g := range res.Gates {
			vs = append(vs, g.Verdict)
		}
		for _, o := range res.Sinks {
			vs = append(vs, o.Verdict)
		}
		if res.Fault != "" {
			vs = append(vs, Deny)
		}
		if res.Verdict != gate.AndAll(vs...) {
			t.Errorf("rollup mismatch: %v != AndAll(%v)", res.Verdict, vs)
		}
		// (4) ESCALATE PROVENANCE: only declared gates escalate.
		if res.Verdict == Escalate {
			found := false
			for _, g := range res.Gates {
				if g.Verdict == Escalate {
					found = true
				}
			}
			if !found {
				t.Errorf("ESCALATE without a gate outcome escalating")
			}
		}
		byId := map[string]Step{}
		for _, st := range steps {
			if _, seen := byId[st.Id]; !seen {
				byId[st.Id] = st
			}
		}
		for _, g := range res.Gates {
			if g.Verdict == Escalate {
				st := byId[g.Id]
				if !st.Escalate || st.Rule == nil || g.Subject == TrustClass(-1) {
					t.Errorf("ESCALATE from undeclared/severed gate %q: %+v", g.Id, g)
				}
			}
		}
		// (5) events hash cleanly; ordering is a real authoritative sink's document index.
		for _, ev := range res.Events {
			if h, err := ev.Hash(); err != nil || len(h) != 64 {
				t.Errorf("event hash invalid")
			}
			i := int(ev.Ordering)
			if i < 0 || i >= nSteps || steps[i].Kind != NodeSink || steps[i].Sensitivity != SinkAuthoritative || steps[i].Field != ev.TargetField {
				t.Errorf("ORDERING %d does not name the emitting authoritative sink", i)
			}
		}
		// (6) determinism.
		if res2 := Eval(recipe, proposal, rh); !reflect.DeepEqual(res, res2) {
			t.Errorf("determinism: results differ")
		}
	})
}
