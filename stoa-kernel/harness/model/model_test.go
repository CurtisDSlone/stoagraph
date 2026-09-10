package model_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

const rh = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sampleRecipe() stag.Recipe {
	set := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "isolate", "notify"}}
	return stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "action"},
		{Id: "act", Kind: stag.NodeSink, In: "action", Sensitivity: stag.SinkAuthoritative,
			Rule: set, RuleID: "actions.approved", Field: "act.args.action", Actor: "policy:remediation"},
		{Id: "log", Kind: stag.NodeSink, In: "action", Sensitivity: stag.SinkBenign, Field: "log.action"},
	}}
}

func TestLocalStub(t *testing.T) {
	s := model.LocalStub{Name: "n", Responses: map[string]string{"a": "x"}, Default: "d"}
	if p, err := s.Propose(context.Background(), model.Request{Input: "a"}); err != nil || p.Value != "x" || p.Model != "localstub:n" {
		t.Errorf("hit: %+v %v", p, err)
	}
	if p, err := s.Propose(context.Background(), model.Request{Input: "miss"}); err != nil || p.Value != "d" || p.Model != "localstub:n" {
		t.Errorf("miss: %+v %v", p, err)
	}
	p1, _ := s.Propose(context.Background(), model.Request{Input: "a"})
	p2, _ := s.Propose(context.Background(), model.Request{Input: "a"})
	if p1 != p2 {
		t.Errorf("determinism: %+v != %+v", p1, p2)
	}

	fail := model.LocalStub{Name: "n", Responses: map[string]string{"a": "x"}, Err: errors.New("boom")}
	if p, err := fail.Propose(context.Background(), model.Request{Input: "a"}); err == nil || p != (model.Proposal{}) {
		t.Errorf("fail path: %+v %v", p, err)
	}
}

func TestDecide(t *testing.T) {
	r := sampleRecipe()
	ctx := context.Background()

	stub := model.LocalStub{Name: "m1", Default: "restart"}
	d, err := model.Decide(ctx, r, rh, stub, model.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.Result, stag.Eval(r, "restart", rh)) {
		t.Errorf("decide != eval")
	}
	if d.Proposal.Value != "restart" || d.Proposal.Model != "localstub:m1" {
		t.Errorf("proposal: %+v", d.Proposal)
	}
	if d.Result.Verdict != stag.Allow || len(d.Result.Events) != 1 {
		t.Errorf("expected allow+event: %+v", d.Result)
	}

	deny := model.LocalStub{Name: "m1", Default: "rm -rf /"}
	dd, _ := model.Decide(ctx, r, rh, deny, model.Request{})
	if dd.Result.Verdict != stag.Deny || len(dd.Result.Events) != 0 ||
		!reflect.DeepEqual(dd.Result, stag.Eval(r, "rm -rf /", rh)) {
		t.Errorf("deny: %+v", dd.Result)
	}

	// fail closed
	fail := model.LocalStub{Name: "m1", Default: "restart", Err: errors.New("timeout")}
	df, ferr := model.Decide(ctx, r, rh, fail, model.Request{})
	if ferr == nil {
		t.Errorf("expected error")
	}
	if df.Result.Verdict != stag.Deny || df.Result.Fault == "" || len(df.Result.Events) != 0 || len(df.Result.Sinks) != 0 {
		t.Errorf("fail-closed: %+v", df.Result)
	}

	// model-independence spot check: different provenance, same value, same verdict
	a := model.LocalStub{Name: "alpha", Default: "restart"}
	b := model.LocalStub{Name: "beta", Default: "restart"}
	da, _ := model.Decide(ctx, r, rh, a, model.Request{})
	db, _ := model.Decide(ctx, r, rh, b, model.Request{})
	if !reflect.DeepEqual(da.Result, db.Result) {
		t.Errorf("model-independence: verdict changed with the model")
	}
	if da.Proposal.Model == db.Proposal.Model {
		t.Errorf("provenance should differ")
	}
}

func FuzzDecideModelIndependence(f *testing.F) {
	f.Add("restart", "gpt", "claude")
	f.Add("rm -rf /", "a", "b")
	f.Add("", "x", "y")
	f.Fuzz(func(t *testing.T, value, ma, mb string) {
		r := sampleRecipe()
		ctx := context.Background()
		a := model.LocalStub{Name: ma, Default: value}
		b := model.LocalStub{Name: mb, Default: value}

		da, erra := model.Decide(ctx, r, rh, a, model.Request{})
		db, errb := model.Decide(ctx, r, rh, b, model.Request{})
		if erra != nil || errb != nil {
			t.Fatalf("unexpected error: %v %v", erra, errb)
		}
		// (1) model-independence: same value -> same verdict regardless of provenance
		if !reflect.DeepEqual(da.Result, db.Result) {
			t.Errorf("MODEL-DEPENDENT verdict for value %q: %q vs %q", value, ma, mb)
		}
		// (2) pure pass-through: Decide adds no trust
		if !reflect.DeepEqual(da.Result, stag.Eval(r, value, rh)) {
			t.Errorf("decide diverged from eval for %q", value)
		}
		// (3) provenance carried
		if da.Proposal.Model != "localstub:"+ma || db.Proposal.Model != "localstub:"+mb {
			t.Errorf("provenance dropped: %q %q", da.Proposal.Model, db.Proposal.Model)
		}
		// (4) events valid + bound to the recipe hash
		for _, ev := range da.Result.Events {
			if h, err := ev.Hash(); err != nil || len(h) != 64 || ev.RecipeHash != rh {
				t.Errorf("event invalid: %q %v", h, err)
			}
		}
	})
}
