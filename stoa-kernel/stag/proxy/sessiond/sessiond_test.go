package sessiond_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/sessiond"
)

// Two recipes gating the SAME tool arg differently — the point of session→recipe: bind the same
// tool to different policies per session and the same call gets different verdicts.
const allowDev = `recipe: allow_dev
version: 1
rules:
  ns.dev: {kind: set_membership, set: ["dev"]}
steps:
  - {id: propose_ns, kind: propose, out: namespace}
  - {id: apply, kind: sink, in: namespace, field: k8s.scale.apply, sensitivity: authoritative, rule: ns.dev, actor: "policy:test"}
`

const onlyProd = `recipe: only_prod
version: 1
rules:
  ns.prod: {kind: set_membership, set: ["prod"]}
steps:
  - {id: propose_ns, kind: propose, out: namespace}
  - {id: apply, kind: sink, in: namespace, field: k8s.scale.apply, sensitivity: authoritative, rule: ns.prod, actor: "policy:test"}
`

func recipeLoader() func(string) ([]byte, error) {
	m := map[string]string{"allow_dev": allowDev, "only_prod": onlyProd}
	return func(name string) ([]byte, error) {
		if src, ok := m[name]; ok {
			return []byte(src), nil
		}
		return nil, fmt.Errorf("no recipe %q", name)
	}
}

type spySink struct {
	mu   sync.Mutex
	recs []stag.DecisionRecord
}

func (s *spySink) Record(_ context.Context, d stag.DecisionRecord) error {
	s.mu.Lock()
	s.recs = append(s.recs, d)
	s.mu.Unlock()
	return nil
}

// count is decisions recorded (allow AND deny); releases is crossings that actually happened.
func (s *spySink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.recs) }
func (s *spySink) releases() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, d := range s.recs {
		n += len(d.Events)
	}
	return n
}

// TestSessionRecipeBinding is the v2 e2e: two sessions bind the SAME tool to DIFFERENT recipes, and
// the same call is allowed in one session and denied in the other; an unknown token is refused; and the
// ONE shared audit sink records BOTH decisions while only the allowed one carries a release.
func TestSessionRecipeBinding(t *testing.T) {
	ctx := context.Background()

	// mock downstream: a scale_deployment tool that just echoes (stands in for k8s-ops).
	down := mcp.NewServer(&mcp.Implementation{Name: "mock-k8s", Version: "0"}, nil)
	down.AddTool(&mcp.Tool{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}},
		func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "scaled by downstream"}}}, nil
		})
	dst, dct := mcp.NewInMemoryTransports()
	if _, err := down.Connect(ctx, dst, nil); err != nil {
		t.Fatalf("downstream connect: %v", err)
	}
	downClient := mcp.NewClient(&mcp.Implementation{Name: "daemon", Version: "0"}, nil)
	downSession, err := downClient.Connect(ctx, dct, nil)
	if err != nil {
		t.Fatalf("downstream client: %v", err)
	}
	defer downSession.Close()

	// the daemon
	sink := &spySink{}
	deps := sessiond.Deps{
		Sink: sink,
		// The fleet: one downstream owning scale_deployment. A route resolves to its owner at bind.
		Fleet: mcpgate.NewFleet([]mcpgate.Downstream{{
			Name: "downstream", Session: downSession,
			Tools: []*mcp.Tool{{Name: "scale_deployment", InputSchema: map[string]any{"type": "object"}}},
		}}),
		LoadRecipe: recipeLoader(),
		Auth:       &auth.Authenticator{Tokens: testTokens}, // control plane ON (Planning/31)
	}
	ts := httptest.NewServer(sessiond.Handler(sessiond.NewRegistry(), deps))
	defer ts.Close()

	// two sessions binding the same tool to different recipes
	tokA := createSession(t, ts.URL, "scale_deployment", "allow_dev", "namespace")
	tokB := createSession(t, ts.URL, "scale_deployment", "only_prod", "namespace")
	if tokA == tokB {
		t.Fatal("session tokens must be distinct")
	}

	// The agent calls the ADVERTISED name (<server>__<tool>); the dispatcher bound it as (tool, server).
	// session A (allow_dev): scale dev -> ALLOW -> forwards to downstream
	if out, isErr := callViaSession(t, ctx, ts.URL, tokA, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); isErr || !strings.Contains(out, "scaled by downstream") {
		t.Fatalf("session A (allow_dev) dev: want forward, got isErr=%v %q", isErr, out)
	}

	// session B (only_prod): the SAME call -> DENY (dev not in {prod}) -> gate error, not forwarded
	if out, _ := callViaSession(t, ctx, ts.URL, tokB, "downstream__scale_deployment", map[string]any{"namespace": "dev"}); strings.Contains(out, "scaled by downstream") || !strings.Contains(out, "stag gate") {
		t.Fatalf("session B (only_prod) dev: want gate deny (no forward), got %q", out)
	}

	// BOTH decisions land on the shared audit log — the blocked attempt is evidence, not noise. But only
	// session A RELEASED anything: B was denied, so it crossed nothing and carries no release.
	if got := sink.count(); got != 2 {
		t.Errorf("shared audit log: want 2 decisions recorded (A's allow + B's deny), got %d", got)
	}
	if got := sink.releases(); got != 1 {
		t.Errorf("only session A released a crossing: want 1, got %d", got)
	}

	// unknown token -> connect fails (getServer returns nil -> 400)
	if _, err := connectMCP(ctx, ts.URL, "deadbeefdeadbeef00000000deadbeef"); err == nil {
		t.Error("connecting with an unknown token must fail closed")
	}
}

// testTokens are the control-plane role secrets used by the daemon tests (Planning/31).
var testTokens = auth.Tokens{Admin: "tok-admin", Approve: "tok-approve", Dispatch: "tok-dispatch", Operator: "tok-operator"}

// postSession POSTs a binding with the given bearer token (empty = anonymous) and returns the status
// and body — the raw primitive the auth tests assert on.
func postSession(t *testing.T, base, token, tool, recipe, gateArg string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"routes":[{"tool":%q,"server":"downstream","recipe":%q,"gateArg":%q}]}`, tool, recipe, gateArg)
	req, err := http.NewRequest(http.MethodPost, base+"/sessions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /sessions: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func createSession(t *testing.T, base, tool, recipe, gateArg string) string {
	t.Helper()
	body := fmt.Sprintf(`{"routes":[{"tool":%q,"server":"downstream","recipe":%q,"gateArg":%q}]}`, tool, recipe, gateArg)
	req, _ := http.NewRequest(http.MethodPost, base+"/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testTokens.Dispatch) // the ORCHESTRATOR's role
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /sessions: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Token == "" {
		t.Fatalf("bad create-session response: %v", err)
	}
	return out.Token
}

func connectMCP(ctx context.Context, base, token string) (*mcp.ClientSession, error) {
	tr := &mcp.StreamableClientTransport{Endpoint: base + "/mcp/" + token}
	c := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil)
	return c.Connect(ctx, tr, nil)
}

func callViaSession(t *testing.T, ctx context.Context, base, token, tool string, args map[string]any) (string, bool) {
	t.Helper()
	sess, err := connectMCP(ctx, base, token)
	if err != nil {
		t.Fatalf("connect session %s: %v", token, err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "transport: " + err.Error(), true
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}
