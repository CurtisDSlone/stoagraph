package openai_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model/openai"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

var _ model.Proposer = openai.Client{}

const rh = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func chatJSON(servedModel, content, finish string) string {
	return fmt.Sprintf(
		`{"id":"chatcmpl-1","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":%q}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
		servedModel, content, finish)
}

func fakeAPI(t *testing.T, status int, body string) (*httptest.Server, *[]byte, *string) {
	t.Helper()
	var last []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &last, &auth
}

func newClient(srv *httptest.Server, mdl, key string) openai.Client {
	return openai.Client{BaseURL: srv.URL + "/v1", APIKey: key, Model: mdl}
}

func TestProposeSuccess(t *testing.T) {
	srv, _, _ := fakeAPI(t, 200, chatJSON("qwen3-coder", "restart", "stop"))
	c := newClient(srv, "qwen3-coder", "k")

	p, err := c.Propose(context.Background(), model.Request{Input: "act"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Value != "restart" || p.Model != "openai:qwen3-coder" {
		t.Errorf("proposal: %+v", p)
	}
	if p2, _ := c.Propose(context.Background(), model.Request{Input: "act"}); p != p2 {
		t.Errorf("nondeterministic: %+v vs %+v", p, p2)
	}

	// finish_reason "length" (truncated) still returns content
	srvL, _, _ := fakeAPI(t, 200, chatJSON("qwen3-coder", "rest", "length"))
	if pl, _ := newClient(srvL, "qwen3-coder", "k").Propose(context.Background(), model.Request{}); pl.Value != "rest" {
		t.Errorf("length: %q", pl.Value)
	}

	// omitted model field -> fall back to c.Model
	srvN, _, _ := fakeAPI(t, 200, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	if pn, _ := newClient(srvN, "local-x", "k").Propose(context.Background(), model.Request{}); pn.Model != "openai:local-x" {
		t.Errorf("model fallback: %q", pn.Model)
	}
}

func TestProposeFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", 500, `{"error":{"message":"boom"}}`},
		{"empty choices", 200, `{"model":"m","choices":[]}`},
		{"content filter", 200, chatJSON("m", "", "content_filter")},
		{"undecodable", 200, `not json at all`},
	}
	for _, tc := range cases {
		srv, _, _ := fakeAPI(t, tc.status, tc.body)
		if p, err := newClient(srv, "m", "k").Propose(context.Background(), model.Request{Input: "x"}); err == nil || p != (model.Proposal{}) {
			t.Errorf("%s: p=%+v err=%v", tc.name, p, err)
		}
	}
}

func TestProposeRequestShape(t *testing.T) {
	srv, last, auth := fakeAPI(t, 200, chatJSON("m", "ok", "stop"))
	c := openai.Client{BaseURL: srv.URL + "/v1", APIKey: "k", Model: "m", MaxTokens: 32}
	if _, err := c.Propose(context.Background(), model.Request{System: "be terse", Input: "do it"}); err != nil {
		t.Fatal(err)
	}
	body := string(*last)
	for _, want := range []string{"do it", "be terse", `"model":"m"`, `"max_tokens":32`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q: %s", want, body)
		}
	}
	for _, banned := range []string{"temperature", "top_p", "top_k"} {
		if strings.Contains(body, banned) {
			t.Errorf("body must not send %q: %s", banned, body)
		}
	}
	if *auth != "Bearer k" {
		t.Errorf("authorization = %q, want Bearer k", *auth)
	}

	// empty system -> no system message; empty key -> no Authorization header
	srv2, last2, auth2 := fakeAPI(t, 200, chatJSON("m", "ok", "stop"))
	c2 := openai.Client{BaseURL: srv2.URL + "/v1", Model: "m"}
	if _, err := c2.Propose(context.Background(), model.Request{Input: "hi"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(*last2), "system") {
		t.Errorf("empty system should not appear: %s", *last2)
	}
	if *auth2 != "" {
		t.Errorf("empty key should send no Authorization: %q", *auth2)
	}
}

func sampleRecipe() stag.Recipe {
	set := &stag.ReleaseRule{Kind: stag.RuleSetMembership, Set: []string{"restart", "isolate", "notify"}}
	return stag.Recipe{Steps: []stag.Step{
		{Id: "p", Kind: stag.NodePropose, Out: "action"},
		{Id: "act", Kind: stag.NodeSink, In: "action", Sensitivity: stag.SinkAuthoritative,
			Rule: set, RuleID: "actions.approved", Field: "act.args.action", Actor: "policy:remediation"},
		{Id: "log", Kind: stag.NodeSink, In: "action", Sensitivity: stag.SinkBenign, Field: "log.action"},
	}}
}

func TestOpenAIDecideZeroTrust(t *testing.T) {
	ctx := context.Background()
	r := sampleRecipe()
	for _, value := range []string{"restart", "rm -rf /"} {
		srv, _, _ := fakeAPI(t, 200, chatJSON("qwen3-coder", value, "stop"))
		c := newClient(srv, "qwen3-coder", "k")

		dc, err := model.Decide(ctx, r, rh, c, model.Request{})
		if err != nil {
			t.Fatalf("decide(openai): %v", err)
		}
		ds, _ := model.Decide(ctx, r, rh, model.LocalStub{Name: "s", Default: value}, model.Request{})

		if !reflect.DeepEqual(dc.Result, stag.Eval(r, value, rh)) {
			t.Errorf("%q: openai decide diverged from eval", value)
		}
		if !reflect.DeepEqual(dc.Result, ds.Result) {
			t.Errorf("%q: verdict changed with the proposer (openai vs stub)", value)
		}
		if dc.Proposal.Model == ds.Proposal.Model {
			t.Errorf("%q: provenance should differ", value)
		}
	}
}
