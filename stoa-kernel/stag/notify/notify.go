// Package notify is the OPTIONAL push side of the human-approval loop (Stage 5): a fire-and-forget
// webhook that POSTs a pending-approval notice to an external system (Slack/PagerDuty/an existing
// change-approval flow) when the gate escalates. It is a NOTIFICATION only — the approval store
// row is the source of truth, and the callback approves via the normal /api/approvals endpoint.
// Enforcement never depends on the webhook: a failed POST is swallowed.
package notify

// file-kw: webhook approval escalate push best-effort async non-blocking notification stage5

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// Webhook returns a proxy.Gate.OnEscalate callback that POSTs each fresh escalation to url. It is
// ASYNC (spawns a goroutine) so it never blocks the deterministic gate decision, and best-effort
// (errors ignored). An empty url returns nil — the loop runs dashboard-only.
func Webhook(url string) func(context.Context, proxy.PendingNotice) {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	return func(_ context.Context, n proxy.PendingNotice) {
		body, err := json.Marshal(n)
		if err != nil {
			return
		}
		go func() {
			// fresh context: the gate's request may end before the POST completes.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
}
