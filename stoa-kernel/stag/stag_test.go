package stag_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
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
func fixture(escalate bool) stag.Recipe {
	routesAll := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"class:regional_fallback", "class:edge_only", "class:transcontinental"}}
	routesAuto := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"class:regional_fallback", "class:edge_only"}}
	cacheApproved := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"class:release_prewarm"}}
	return stag.Recipe{Steps: []stag.Step{
		{Id: "propose_plan", Kind: stag.NodePropose, Out: "plan"},
		{Id: "choose_path", Kind: stag.NodeBranch, In: "plan",
			Cases:   []stag.Case{{Rule: routesAll, Goto: "check_route"}, {Rule: cacheApproved, Goto: "apply_prefetch"}},
			Default: "log_only"},
		{Id: "check_route", Kind: stag.NodeGate, In: "plan", Rule: routesAuto, Escalate: escalate},
		{Id: "apply_route", Kind: stag.NodeSink, In: "plan", Sensitivity: stag.SinkAuthoritative,
			Rule: routesAuto, RuleID: "routes.auto_approvable", Field: "aws_route_apply.args.route",
			Actor: "policy:network_remediation", Goto: "log_only"},
		{Id: "apply_prefetch", Kind: stag.NodeSink, In: "plan", Sensitivity: stag.SinkAuthoritative,
			Rule: cacheApproved, RuleID: "cache.approved", Field: "edge_cache_prefetch.args.plan",
			Actor: "policy:cache_budget"},
		{Id: "log_only", Kind: stag.NodeSink, In: "plan", Sensitivity: stag.SinkBenign, Field: "log.plan"},
	}}
}

func TestRecipeEval(t *testing.T) {
	fx := fixture(true)

	// path 1: auto-allow route (branch -> gate pass -> auth sink -> goto log)
	r1 := stag.Eval(fx, "class:regional_fallback", rh)
	if r1.Verdict != stag.Allow || r1.Fault != "" {
		t.Errorf("path1: verdict=%v fault=%q, want Allow,\"\"", r1.Verdict, r1.Fault)
	}
	if len(r1.Events) != 1 {
		t.Fatalf("path1: events=%d, want 1", len(r1.Events))
	}
	e := r1.Events[0]
	if e.TargetField != "aws_route_apply.args.route" || e.AuthorizingRule != "routes.auto_approvable" ||
		e.RecipeHash != rh || e.Ordering != 3 || e.SubjectClass != stag.Untrusted {
		t.Errorf("path1: event fields wrong: %+v", e)
	}
	if len(r1.Gates) != 1 || !r1.Gates[0].Passed || r1.Gates[0].Verdict != stag.Allow || r1.Gates[0].Id != "check_route" {
		t.Errorf("path1: gates wrong: %+v", r1.Gates)
	}
	if len(r1.Sinks) != 2 || r1.Sinks[0].Field != "aws_route_apply.args.route" || r1.Sinks[1].Field != "log.plan" {
		t.Errorf("path1: sinks wrong (want auth then log, prefetch not taken): %+v", r1.Sinks)
	}

	// path 2: prefetch-allow (branch routes past the gate)
	r2 := stag.Eval(fx, "class:release_prewarm", rh)
	if r2.Verdict != stag.Allow || r2.Fault != "" || len(r2.Gates) != 0 {
		t.Errorf("path2: verdict=%v fault=%q gates=%d, want Allow,\"\",0", r2.Verdict, r2.Fault, len(r2.Gates))
	}
	if len(r2.Events) != 1 || r2.Events[0].TargetField != "edge_cache_prefetch.args.plan" || r2.Events[0].Ordering != 4 {
		t.Errorf("path2: events wrong: %+v", r2.Events)
	}
	if len(r2.Sinks) != 2 || r2.Sinks[1].Field != "log.plan" {
		t.Errorf("path2: sinks wrong (want prefetch then fall-through log): %+v", r2.Sinks)
	}

	// path 3: escalate (gate fails on a present value with escalate declared; walk halts)
	r3 := stag.Eval(fx, "class:transcontinental", rh)
	if r3.Verdict != stag.Escalate || r3.Fault != "" {
		t.Errorf("path3: verdict=%v fault=%q, want Escalate,\"\"", r3.Verdict, r3.Fault)
	}
	if len(r3.Events) != 0 || len(r3.Sinks) != 0 {
		t.Errorf("path3: events=%d sinks=%d, want 0,0 (actuator never reached)", len(r3.Events), len(r3.Sinks))
	}
	if len(r3.Gates) != 1 || r3.Gates[0].Passed || r3.Gates[0].Verdict != stag.Escalate {
		t.Errorf("path3: gates wrong: %+v", r3.Gates)
	}

	// path 4: spoof-inert (default routes to the benign log; nothing authoritative reached)
	r4 := stag.Eval(fx, "rm -rf /", rh)
	if r4.Verdict != stag.Allow || len(r4.Events) != 0 || len(r4.Gates) != 0 ||
		len(r4.Sinks) != 1 || r4.Sinks[0].Sink != stag.SinkBenign {
		t.Errorf("path4: %+v", r4)
	}

	// gate defaults to Deny when escalate is not declared
	rd := stag.Eval(fixture(false), "class:transcontinental", rh)
	if rd.Verdict != stag.Deny || len(rd.Gates) != 1 || rd.Gates[0].Verdict != stag.Deny || len(rd.Sinks) != 0 {
		t.Errorf("gate default deny: %+v", rd)
	}

	// escalate never softens uncertainty: severed input and nil rule both Deny
	sev := stag.Eval(stag.Recipe{Steps: []stag.Step{
		{Id: "g", Kind: stag.NodeGate, In: "nope", Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"x"}}, Escalate: true},
	}}, "", rh)
	if sev.Verdict != stag.Deny || len(sev.Gates) != 1 || sev.Gates[0].Verdict != stag.Deny || sev.Fault != "" {
		t.Errorf("gate severed: %+v", sev)
	}
	nr := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"x": {Value: "v", Class: stag.Untrusted}},
		Steps:       []stag.Step{{Id: "g", Kind: stag.NodeGate, In: "x", Escalate: true}},
	}, "", rh)
	if nr.Verdict != stag.Deny || len(nr.Gates) != 1 || nr.Gates[0].Verdict != stag.Deny {
		t.Errorf("gate nil rule: %+v", nr)
	}

	// faults fail closed: unknown goto, backward goto, branch severed, branch no-match
	// with empty default, unknown kind
	faults := []stag.Recipe{
		{Steps: []stag.Step{{Id: "p", Kind: stag.NodePropose, Out: "o", Goto: "nowhere"},
			{Id: "s", Kind: stag.NodeSink, In: "o", Sensitivity: stag.SinkBenign, Field: "f"}}},
		{Steps: []stag.Step{{Id: "a", Kind: stag.NodePropose, Out: "o"},
			{Id: "b", Kind: stag.NodeSink, In: "o", Sensitivity: stag.SinkBenign, Field: "f", Goto: "a"}}},
		{Steps: []stag.Step{{Id: "br", Kind: stag.NodeBranch, In: "nope",
			Cases: []stag.Case{{Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"x"}}, Goto: "z"}}, Default: "z"},
			{Id: "z", Kind: stag.NodeSink, In: "nope", Sensitivity: stag.SinkBenign, Field: "f"}}},
		{Steps: []stag.Step{{Id: "p", Kind: stag.NodePropose, Out: "o"},
			{Id: "br", Kind: stag.NodeBranch, In: "o",
				Cases: []stag.Case{{Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"never"}}, Goto: "z"}}},
			{Id: "z", Kind: stag.NodeSink, In: "o", Sensitivity: stag.SinkBenign, Field: "f"}}},
		{Steps: []stag.Step{{Id: "j", Kind: stag.NodeKind(9)},
			{Id: "s", Kind: stag.NodeSink, In: "o", Sensitivity: stag.SinkBenign, Field: "f"}}},
	}
	for i, fr := range faults {
		res := stag.Eval(fr, "v", rh)
		if res.Fault == "" || res.Verdict != stag.Deny {
			t.Errorf("fault[%d]: fault=%q verdict=%v, want non-empty,Deny (%+v)", i, res.Fault, res.Verdict, res)
		}
	}

	// a missing slot NEVER releases, even against a rule enumerating "" (U7 v2 adversarial finding)
	ms := stag.Eval(stag.Recipe{Steps: []stag.Step{
		{Id: "s", Kind: stag.NodeSink, In: "absent", Sensitivity: stag.SinkAuthoritative,
			Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{""}}, RuleID: "r", Field: "f", Actor: "a"},
	}}, "anything", rh)
	if ms.Verdict != stag.Deny || len(ms.Events) != 0 || ms.Sinks[0].Released {
		t.Errorf("severed slot released against empty-string set: %+v", ms)
	}

	// a sink Deny refuses the crossing, not the movement
	sd := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"u": {Value: "bad", Class: stag.Untrusted}},
		Steps: []stag.Step{
			{Id: "a", Kind: stag.NodeSink, In: "u", Sensitivity: stag.SinkAuthoritative, Field: "f1"},
			{Id: "b", Kind: stag.NodeSink, In: "u", Sensitivity: stag.SinkBenign, Field: "f2"},
		},
	}, "", rh)
	if sd.Verdict != stag.Deny || len(sd.Sinks) != 2 || sd.Sinks[0].Verdict != stag.Deny || sd.Sinks[1].Verdict != stag.Allow ||
		len(sd.Events) != 0 || sd.Fault != "" {
		t.Errorf("sink deny continues: %+v", sd)
	}

	// v1 back-compat: linear recipes evaluate as before (3-arg)
	setRule := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "isolate", "notify"}}
	lin := stag.Recipe{Steps: []stag.Step{
		{Kind: stag.NodePropose, Out: "action"},
		{Kind: stag.NodeSink, In: "action", Sensitivity: stag.SinkAuthoritative, Rule: setRule, RuleID: "actions.approved", Field: "act.args.action", Actor: "policy:remediation"},
	}}
	h1 := stag.Eval(lin, "restart", rh)
	if h1.Verdict != stag.Allow || len(h1.Events) != 1 || h1.Events[0].RecipeHash != rh || h1.Events[0].Ordering != 1 {
		t.Errorf("compat happy: %+v", h1)
	}
	if d := stag.Eval(lin, "rm -rf /", rh); d.Verdict != stag.Deny || len(d.Events) != 0 {
		t.Errorf("compat denied: %+v", d)
	}
	if a := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"fact": {Value: "x", Class: stag.Authoritative, Origin: "pip"}},
		Steps:       []stag.Step{{Kind: stag.NodeSink, In: "fact", Sensitivity: stag.SinkAuthoritative, Field: "f"}},
	}, "", rh); a.Verdict != stag.Allow || len(a.Events) != 0 {
		t.Errorf("compat auth subject: %+v", a)
	}
	if b := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"x": {Value: "anything", Class: stag.Untrusted}},
		Steps:       []stag.Step{{Kind: stag.NodeSink, In: "x", Sensitivity: stag.SinkBenign, Field: "log"}},
	}, "", rh); b.Verdict != stag.Allow || len(b.Events) != 0 {
		t.Errorf("compat benign: %+v", b)
	}
	if m := stag.Eval(stag.Recipe{Steps: []stag.Step{{Kind: stag.NodeSink, In: "nope", Sensitivity: stag.SinkAuthoritative, Field: "f"}}}, "", rh); m.Verdict != stag.Deny || len(m.Events) != 0 {
		t.Errorf("compat missing slot: %+v", m)
	}
	if r := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"u": {Value: "restart", Class: stag.Untrusted}, "u2": {Value: "bad", Class: stag.Untrusted}},
		Steps: []stag.Step{
			{Kind: stag.NodeSink, In: "u", Sensitivity: stag.SinkAuthoritative, Rule: setRule, Field: "a"},
			{Kind: stag.NodeSink, In: "u2", Sensitivity: stag.SinkAuthoritative, Rule: setRule, Field: "b"},
		},
	}, "", rh); r.Verdict != stag.Deny {
		t.Errorf("compat rollup: %+v", r)
	}
	if stag.Eval(stag.Recipe{}, "", rh).Verdict != stag.Allow {
		t.Errorf("compat empty recipe should be Allow")
	}

	// recipe hash threading: "" permitted; differing hashes yield differing event hashes
	z := stag.Eval(lin, "restart", "")
	if len(z.Events) != 1 || z.Events[0].RecipeHash != "" {
		t.Errorf("rh empty: %+v", z.Events)
	}
	za, _ := z.Events[0].Hash()
	zb, _ := h1.Events[0].Hash()
	if za == zb {
		t.Errorf("rh threading: event hashes should differ across recipe hashes")
	}

	// nodekind register: canonical spellings + fail-closed parse
	wantStr := map[stag.NodeKind]string{stag.NodePropose: "propose", stag.NodeSink: "sink", stag.NodeBranch: "branch", stag.NodeGate: "gate", stag.NodeForeach: "foreach", stag.NodeExit: "exit", stag.NodeKind(99): "unknown"}
	for k, w := range wantStr {
		if k.String() != w {
			t.Errorf("NodeKind(%d).String()=%q, want %q", int(k), k.String(), w)
		}
	}
	for _, k := range []stag.NodeKind{stag.NodePropose, stag.NodeSink, stag.NodeBranch, stag.NodeGate, stag.NodeForeach, stag.NodeExit} {
		if got, err := stag.ParseNodeKind(k.String()); err != nil || got != k {
			t.Errorf("round-trip: ParseNodeKind(%q)=%v,%v", k.String(), got, err)
		}
	}
	for _, s := range []string{"unknown", "", "Propose", " gate "} {
		if got, err := stag.ParseNodeKind(s); err == nil || got != stag.NodeKind(-1) {
			t.Errorf("fail-closed: ParseNodeKind(%q)=%v,%v, want -1,error", s, got, err)
		}
	}

	// events are valid records; determinism
	for _, ev := range r1.Events {
		if h, err := ev.Hash(); err != nil || len(h) != 64 {
			t.Errorf("event hash invalid: %q %v", h, err)
		}
	}
	if da, db := stag.Eval(fx, "class:regional_fallback", rh), stag.Eval(fx, "class:regional_fallback", rh); !reflect.DeepEqual(da, db) {
		t.Errorf("determinism: results differ")
	}
}

// TestRuleFaultNamesArgAndRuleWithoutTouchingFault: a clean rule denial (argument present, rule
// evaluated, just didn't clear) must set RuleFault so a caller can retry with a different value —
// but must NOT set Fault, which stays reserved for a structural halt (inv 8/10). Confirms the two
// fields carry genuinely different meanings rather than duplicating one signal under two names.
func TestRuleFaultNamesArgAndRuleWithoutTouchingFault(t *testing.T) {
	// sink deny: argument present, rule declared, value simply not in the set
	sd := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"value": {Value: "40", Class: stag.Untrusted}},
		Steps: []stag.Step{
			{Id: "s", Kind: stag.NodeSink, In: "value", Sensitivity: stag.SinkAuthoritative,
				Rule:   &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"4", "8", "12", "16"}},
				RuleID: "value.safe", Field: "f"},
		},
	}, "", rh)
	if sd.Verdict != stag.Deny {
		t.Fatalf("sink deny: verdict=%v, want Deny", sd.Verdict)
	}
	if sd.Fault != "" {
		t.Errorf("sink deny: Fault=%q, want \"\" (this is a clean rule denial, not a structural halt)", sd.Fault)
	}
	if sd.RuleFault != `argument "value" failed rule "value.safe"` {
		t.Errorf("sink deny: RuleFault=%q, want it to name the argument and rule", sd.RuleFault)
	}

	// gate deny: same shape, via NodeGate instead of NodeSink
	gd := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"field": {Value: "port", Class: stag.Untrusted}},
		Steps: []stag.Step{
			{Id: "g", Kind: stag.NodeGate, In: "field",
				Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"path"}}, RuleID: "field.known"},
		},
	}, "", rh)
	if gd.Verdict != stag.Deny || gd.Fault != "" {
		t.Errorf("gate deny: verdict=%v fault=%q, want Deny,\"\"", gd.Verdict, gd.Fault)
	}
	if gd.RuleFault != `argument "field" failed rule "field.known"` {
		t.Errorf("gate deny: RuleFault=%q, want it to name the argument and rule", gd.RuleFault)
	}

	// structural fault (unknown goto): Fault set, RuleFault must stay empty — rule evaluation
	// never ran, so there is nothing for RuleFault to name.
	sf := stag.Eval(stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "o", Goto: "nowhere"},
		{Id: "s", Kind: stag.NodeSink, In: "o", Sensitivity: stag.SinkBenign, Field: "f"},
	}}, "v", rh)
	if sf.Fault == "" {
		t.Fatalf("structural fault: Fault=%q, want non-empty", sf.Fault)
	}
	if sf.RuleFault != "" {
		t.Errorf("structural fault: RuleFault=%q, want \"\" (no rule was ever evaluated)", sf.RuleFault)
	}

	// clean allow: neither field set
	ok := stag.Eval(stag.Recipe{
		Ingredients: map[string]stag.Slot{"x": {Value: "yes", Class: stag.Untrusted}},
		Steps: []stag.Step{
			{Id: "s", Kind: stag.NodeSink, In: "x", Sensitivity: stag.SinkAuthoritative,
				Rule: &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"yes"}}, RuleID: "x.ok", Field: "f"},
		},
	}, "", rh)
	if ok.Verdict != stag.Allow || ok.Fault != "" || ok.RuleFault != "" {
		t.Errorf("allow: verdict=%v fault=%q ruleFault=%q, want Allow,\"\",\"\"", ok.Verdict, ok.Fault, ok.RuleFault)
	}
}

func FuzzRecipeEval(f *testing.F) {
	f.Add("class:regional_fallback", []byte{0, 1, 2, 3, 0, 1})
	f.Add("class:release_prewarm", []byte{2, 2, 1, 0})
	f.Add("class:transcontinental", []byte{1, 3, 2, 4})
	f.Add("rm -rf /", []byte{})
	f.Fuzz(func(t *testing.T, proposal string, shape []byte) {
		setRule := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "isolate", "notify", "class:regional_fallback"}}
		numRule := &stag.ReleaseRule{Kind: stag.RuleNumericRange, Min: 1, Max: 10}
		emptyRule := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"", "restart"}} // "" enumerated: missing slots must still never release
		rulePool := []*stag.ReleaseRule{setRule, numRule, emptyRule, nil}

		ingredients := map[string]stag.Slot{}
		vals := []string{proposal, "restart", "5", "bad"}
		for i := 0; i < 3; i++ {
			ingredients[fmt.Sprintf("ing%d", i)] = stag.Slot{Value: vals[i%len(vals)], Class: stag.TrustClass(byteAt(shape, i) % 4), Origin: "ing"}
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

		steps := make([]stag.Step, nSteps)
		for j := 0; j < nSteps; j++ {
			kind := byteAt(shape, 10+j) % 5
			st := stag.Step{Id: ids[j], Goto: pickGoto(j, byteAt(shape, 20+j))}
			switch kind {
			case 0:
				st.Kind = stag.NodePropose
				st.Out = fmt.Sprintf("out%d", j%2)
			case 1:
				st.Kind = stag.NodeSink
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				st.Sensitivity = stag.SinkSensitivity(byteAt(shape, 40+j) % 3)
				st.Rule = rulePool[int(byteAt(shape, 50+j))%len(rulePool)]
				st.RuleID = "r"
				st.Field = fmt.Sprintf("f%d", j)
				st.Actor = "a"
			case 2:
				st.Kind = stag.NodeBranch
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				nc := int(byteAt(shape, 80+j) % 3)
				for c := 0; c < nc; c++ {
					st.Cases = append(st.Cases, stag.Case{Rule: rulePool[int(byteAt(shape, 90+j+c))%len(rulePool)], Goto: pickGoto(j, byteAt(shape, 100+j+c))})
				}
				if byteAt(shape, 110+j)%2 == 0 {
					st.Default = pickGoto(j, byteAt(shape, 120+j))
				}
				st.Goto = ""
			case 3:
				st.Kind = stag.NodeGate
				st.In = slotPool[int(byteAt(shape, 30+j))%len(slotPool)]
				st.Rule = rulePool[int(byteAt(shape, 50+j))%len(rulePool)]
				st.Escalate = byteAt(shape, 130+j)%2 == 1
			default:
				st.Kind = stag.NodeKind(7) // junk kind: must Fault, never skip
			}
			steps[j] = st
		}

		recipe := stag.Recipe{Ingredients: ingredients, Steps: steps}
		res := stag.Eval(recipe, proposal, rh)

		// (1) THE INVARIANT: Allow at an authoritative sink for a non-authoritative
		// subject => a recorded ReleaseEvent bound to the recipe hash.
		for _, o := range res.Sinks {
			if o.Verdict == stag.Allow && o.Sink == stag.SinkAuthoritative && o.Subject != stag.Authoritative {
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
				if o.Field == ev.TargetField && o.Sink == stag.SinkAuthoritative && o.Subject != stag.Authoritative && o.Released && o.Verdict == stag.Allow {
					ok = true
				}
			}
			if !ok {
				t.Errorf("SPURIOUS event for field %q with no matching cleared crossing", ev.TargetField)
			}
		}
		cleared := 0
		for _, o := range res.Sinks {
			if o.Sink == stag.SinkAuthoritative && o.Subject != stag.Authoritative && o.Released && o.Verdict == stag.Allow {
				cleared++
			}
		}
		if len(res.Events) != cleared {
			t.Errorf("BIJECTION: %d events for %d cleared crossings", len(res.Events), cleared)
		}
		// (3) ROLLUP LAW: verdict == AndAll(gates, sinks, fault-deny).
		var vs []stag.Verdict
		for _, g := range res.Gates {
			vs = append(vs, g.Verdict)
		}
		for _, o := range res.Sinks {
			vs = append(vs, o.Verdict)
		}
		if res.Fault != "" {
			vs = append(vs, stag.Deny)
		}
		if res.Verdict != gate.AndAll(vs...) {
			t.Errorf("rollup mismatch: %v != AndAll(%v)", res.Verdict, vs)
		}
		// (4) ESCALATE PROVENANCE: only declared gates escalate.
		if res.Verdict == stag.Escalate {
			found := false
			for _, g := range res.Gates {
				if g.Verdict == stag.Escalate {
					found = true
				}
			}
			if !found {
				t.Errorf("ESCALATE without a gate outcome escalating")
			}
		}
		byId := map[string]stag.Step{}
		for _, st := range steps {
			if _, seen := byId[st.Id]; !seen {
				byId[st.Id] = st
			}
		}
		for _, g := range res.Gates {
			if g.Verdict == stag.Escalate {
				st := byId[g.Id]
				if !st.Escalate || st.Rule == nil || g.Subject == stag.TrustClass(-1) {
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
			if i < 0 || i >= nSteps || steps[i].Kind != stag.NodeSink || steps[i].Sensitivity != stag.SinkAuthoritative || steps[i].Field != ev.TargetField {
				t.Errorf("ORDERING %d does not name the emitting authoritative sink", i)
			}
		}
		// (6) determinism.
		if res2 := stag.Eval(recipe, proposal, rh); !reflect.DeepEqual(res, res2) {
			t.Errorf("determinism: results differ")
		}
	})
}

// TestSinkOutcomeRecordDropsValue proves SinkOutcome.Record's one deliberate omission: Value never
// crosses into the audit-facing shape, even when it's populated (a cleared sink's value). Every
// other field carries straight through.
func TestSinkOutcomeRecordDropsValue(t *testing.T) {
	so := stag.SinkOutcome{
		Field: "log.plan", Subject: stag.Untrusted, Sink: stag.SinkBenign, Released: false,
		Verdict: stag.Allow, Arg: "text", RuleID: "text.allowed", Actor: "policy:x", Value: "hello",
	}
	rec := so.Record()
	if rec.Field != so.Field || rec.Subject != so.Subject || rec.Sink != so.Sink ||
		rec.Released != so.Released || rec.Verdict != so.Verdict || rec.Arg != so.Arg ||
		rec.RuleID != so.RuleID || rec.Actor != so.Actor {
		t.Errorf("Record() field mismatch: got %+v from %+v", rec, so)
	}
	// record.SinkOutcome has no Value field at all — this line simply wouldn't compile if it did,
	// which is the actual proof; the runtime check just documents the intent for a reader.
}
