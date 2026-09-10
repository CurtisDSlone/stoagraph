package agent

// file-kw: approval poll escalation signed-release retry dispatch-role poll-only never-approve human-in-the-loop

// The live human-approval loop (stag Stage 5, orchestrator side). When the gate ESCALATES an
// approval-gated call, stag-proxy returns it as an error with the approval id in the result _meta.
// The orchestrator HOLDS the exact call, waits for a human to approve in the console (or via a
// webhook callback), then REPLAYS the same call verbatim with the signed release token. The model
// never re-decides — the harness controls the retry, so a released action is exactly the one that
// escalated. A denial or timeout ends the call as an error the model sees.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ApprovalConfig drives the wait for a human decision. A nil *ApprovalConfig disables the loop
// (an escalate stays an error the model sees, as before).
//
// Token is the control-plane `dispatch` secret (Planning/31): it admits the POLL (GET
// /api/approvals/{id}) and NOTHING more. The orchestrator is deliberately NOT given the `approve`
// role — it waits on a human, it can never be the human. What unblocks the retry is the ed25519
// SIGNED RELEASE the human's approval produced (a per-action signature, not a credential).
type ApprovalConfig struct {
	BaseURL string        // stag-serve base, e.g. "http://localhost:8080"
	Token   string        // the `dispatch` control-plane token — poll only, NEVER approve
	Poll    time.Duration // interval between status checks
	Timeout time.Duration // give up (and report a timeout) after this long
	HTTP    *http.Client
}

// NewApprovalConfig returns a config with sensible demo defaults (poll 2s, wait up to 10m).
func NewApprovalConfig(baseURL, token string) *ApprovalConfig {
	if baseURL == "" {
		return nil
	}
	return &ApprovalConfig{
		BaseURL: baseURL,
		Token:   token,
		Poll:    2 * time.Second,
		Timeout: 10 * time.Minute,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// EscalationID returns the approval id if this gate result is an approval-gated ESCALATE (i.e. the
// call is held awaiting a human). It reads the structured gate metadata the proxy set in _meta.
func EscalationID(res *mcp.CallToolResult) (string, bool) {
	if res == nil || res.Meta == nil {
		return "", false
	}
	raw, ok := res.Meta["stag"]
	if !ok {
		return "", false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	if fmt.Sprint(m["verdict"]) != "escalate" {
		return "", false
	}
	id, _ := m["approvalId"].(string)
	return id, id != ""
}

// approvalStatus is the subset of GET /api/approvals/{id} the orchestrator needs.
type approvalStatus struct {
	Status string `json:"status"` // pending | approved | denied | consumed
	Token  string `json:"token"`  // present only when approved
}

// Await polls until the approval is decided. It returns the signed token on approval, or a status
// ("denied" | "timeout" | "consumed") with an empty token otherwise.
func (a *ApprovalConfig) Await(ctx context.Context, id string) (token, status string, err error) {
	deadline := time.Now().Add(a.Timeout)
	for {
		st, gerr := a.get(ctx, id)
		if gerr != nil {
			return "", "", gerr
		}
		switch st.Status {
		case "approved":
			return st.Token, "approved", nil
		case "denied":
			return "", "denied", nil
		case "consumed":
			return "", "consumed", nil // already spent — can't release again
		}
		if time.Now().After(deadline) {
			return "", "timeout", nil
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(a.Poll):
		}
	}
}

func (a *ApprovalConfig) get(ctx context.Context, id string) (approvalStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BaseURL+"/api/approvals/"+id, nil)
	if err != nil {
		return approvalStatus{}, err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token) // `dispatch` — poll only
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return approvalStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return approvalStatus{}, fmt.Errorf("approvals GET %s: 401 — the orchestrator's `dispatch` token is missing or wrong", id)
	}
	if resp.StatusCode != http.StatusOK {
		return approvalStatus{}, fmt.Errorf("approvals GET %s: HTTP %d", id, resp.StatusCode)
	}
	var st approvalStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return approvalStatus{}, err
	}
	return st, nil
}
