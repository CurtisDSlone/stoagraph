package serve_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
)

const policySrc = `recipe: write_note_policy
version: 1
rules:
  note.allowed:
    kind: set_membership
    set: ["hello", "status-ok", "deploy-done"]
steps:
  - id: propose_text
    kind: propose
    out: text
  - id: apply
    kind: sink
    in: text
    field: mcp.write_note.text
    sensitivity: authoritative
    rule: note.allowed
    actor: "policy:mcp_proxy"
`

func newServer(t testing.TB, logPath string) *serve.Server {
	t.Helper()
	p, err := recipe.Parse([]byte(policySrc))
	if err != nil {
		t.Fatal(err)
	}
	gate := proxy.Gate{Routes: proxy.Router{
		"write_note": {Recipe: p.Recipe, RecipeHash: p.SemanticHash, GateArg: "text"},
	}}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		gate.Sink = egress.NewJSONLSink(f)
	}
	return &serve.Server{
		Gate:     gate,
		LogPath:  logPath,
		Policies: []serve.PolicyView{{Tool: "write_note", Recipe: "write_note_policy", GateArg: "text"}},
		// these tests exercise handler LOGIC; the control plane's role map has its own test (auth_test.go)
		Auth: &auth.Authenticator{Disabled: true},
	}
}

func do(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeDecision(t *testing.T, w *httptest.ResponseRecorder) serve.DecisionView {
	t.Helper()
	var d serve.DecisionView
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("response not a DecisionView: %q (%v)", w.Body.String(), err)
	}
	return d
}

func TestDecideAllowed(t *testing.T) {
	h := newServer(t, "").Handler()
	w := do(t, h, "POST", "/api/decide", []byte(`{"tool":"write_note","args":{"text":"hello"}}`))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d ct=%q", w.Code, w.Header().Get("Content-Type"))
	}
	d := decodeDecision(t, w)
	if d.Verdict != "allow" || !d.Forward || d.Value != "hello" || d.RuleFired == "" {
		t.Errorf("decision: %+v", d)
	}
	if d.SubjectClass != "untrusted" || d.Chain.Decide != "allow" || d.Chain.Act != "ok" || len(d.Events) == 0 {
		t.Errorf("view detail: %+v", d)
	}
}

func TestDecideUnknownToolDenied(t *testing.T) {
	h := newServer(t, "").Handler()
	w := do(t, h, "POST", "/api/decide", []byte(`{"tool":"delete_everything","args":{}}`))
	if w.Code != 200 {
		t.Fatalf("unknown tool is a valid request: status=%d", w.Code)
	}
	d := decodeDecision(t, w)
	if d.Verdict != "deny" || d.Forward || d.Chain.Act != "skip" {
		t.Errorf("unknown tool must be denied, not forwarded: %+v", d)
	}
}

func TestDecideFailsClosed(t *testing.T) {
	h := newServer(t, "").Handler()
	if w := do(t, h, "POST", "/api/decide", []byte(`{not json`)); w.Code != 400 {
		t.Errorf("malformed body must be 400, got %d", w.Code)
	}
	if w := do(t, h, "POST", "/api/decide", []byte(`{"args":{}}`)); w.Code != 400 {
		t.Errorf("empty tool must be 400, got %d", w.Code)
	}
	if w := do(t, h, "GET", "/api/decide", nil); w.Code != 405 {
		t.Errorf("GET on decide must be 405, got %d", w.Code)
	}
}

func TestLogEndpoint(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	s := newServer(t, logPath)
	h := s.Handler()

	// no log yet
	var lv serve.LogView
	w := do(t, h, "GET", "/api/log", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &lv); err != nil {
		t.Fatalf("log not JSON: %v", err)
	}
	if w.Code != 200 || lv.Verify.Count != 0 {
		t.Errorf("empty log: status=%d count=%d", w.Code, lv.Verify.Count)
	}

	// two allowed decides record crossings
	do(t, h, "POST", "/api/decide", []byte(`{"tool":"write_note","args":{"text":"hello"}}`))
	do(t, h, "POST", "/api/decide", []byte(`{"tool":"write_note","args":{"text":"status-ok"}}`))

	w = do(t, h, "GET", "/api/log", nil)
	lv = serve.LogView{}
	_ = json.Unmarshal(w.Body.Bytes(), &lv)
	if lv.Verify.Count == 0 || lv.Verify.Head == "" || lv.Verify.Error != "" {
		t.Errorf("log after decides: %+v", lv.Verify)
	}
}

func TestPoliciesAndHealth(t *testing.T) {
	h := newServer(t, "").Handler()
	w := do(t, h, "GET", "/api/policies", nil)
	var pols []serve.PolicyView
	if err := json.Unmarshal(w.Body.Bytes(), &pols); err != nil || w.Code != 200 {
		t.Fatalf("policies: status=%d err=%v", w.Code, err)
	}
	if len(pols) != 1 || pols[0].Tool != "write_note" {
		t.Errorf("policies: %+v", pols)
	}

	if w := do(t, h, "GET", "/api/health", nil); w.Code != 200 {
		t.Errorf("health: %d", w.Code)
	}
	if w := do(t, h, "GET", "/api/nope", nil); w.Code != 404 {
		t.Errorf("unknown path must 404: %d", w.Code)
	}
	// CORS preflight
	w = do(t, h, "OPTIONS", "/api/decide", nil)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Errorf("preflight: status=%d acao=%q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}
}

// wellFormedDecide mirrors the handler's accept rule for the fuzz oracle: the body
// must decode into {tool, args:map[string]string} with a non-empty tool.
func wellFormedDecide(body []byte) bool {
	var req struct {
		Tool string            `json:"tool"`
		Args map[string]string `json:"args"`
	}
	return json.Unmarshal(body, &req) == nil && req.Tool != ""
}

func FuzzDecideHandler(f *testing.F) {
	f.Add([]byte(`{"tool":"write_note","args":{"text":"hello"}}`))
	f.Add([]byte(`{not json`))
	f.Add([]byte(`{"args":{}}`))
	f.Add([]byte(`[1,2,3]`))
	h := newServer(f, "").Handler()
	f.Fuzz(func(t *testing.T, body []byte) {
		w := do2(h, body)
		if w.Code == 0 {
			t.Fatalf("no status written")
		}
		if w.Body.Len() > 0 && !json.Valid(w.Body.Bytes()) {
			t.Fatalf("response not valid JSON: %q", w.Body.String())
		}
		if wellFormedDecide(body) {
			// a well-formed decide is gated -> 200 with a valid verdict
			if w.Code != 200 {
				t.Fatalf("well-formed decide must be 200, got %d for %q", w.Code, body)
			}
			var d serve.DecisionView
			if json.Unmarshal(w.Body.Bytes(), &d) != nil ||
				(d.Verdict != "allow" && d.Verdict != "deny" && d.Verdict != "escalate") {
				t.Fatalf("200 must carry a DecisionView with a real verdict: %q", w.Body.String())
			}
		} else if w.Code != 400 {
			// not a well-formed decide -> fail closed (400)
			t.Fatalf("malformed decide must be 400, got %d for %q", w.Code, body)
		}
	})
}

func do2(h http.Handler, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/decide", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
