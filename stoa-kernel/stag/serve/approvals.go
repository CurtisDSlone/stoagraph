package serve

// file-kw: approval endpoints list approve deny signed-release mint ed25519 pending queue stage5

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

// kw: approval view id tool args status token-present fingerprint recipe timestamps
type ApprovalView struct {
	ID          string            `json:"id"`
	Tool        string            `json:"tool"`
	Args        map[string]string `json:"args"`
	Fingerprint string            `json:"fingerprint"`
	Recipe      string            `json:"recipe,omitempty"`
	Status      string            `json:"status"`
	TokenIssued bool              `json:"tokenIssued"` // whether a signed release has been minted
	Reason      string            `json:"reason,omitempty"`
	CreatedAt   string            `json:"createdAt,omitempty"`
	DecidedAt   string            `json:"decidedAt,omitempty"`
}

// GET /api/approvals[?status=pending] — the human-approval queue. Default (no status) returns all
// rows, newest first; the dashboard filters to `pending`. The signed token is NEVER exposed here
// (only whether one was issued) — the orchestrator fetches it from the approve response.
func (s *Server) handleApprovalList(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, []ApprovalView{})
		return
	}
	rows, err := s.Store.ListApprovals(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	out := make([]ApprovalView, 0, len(rows))
	for _, a := range rows {
		out = append(out, ApprovalView{
			ID: a.ID, Tool: a.Tool, Args: decodeArgs(a.ArgsJSON), Fingerprint: a.Fingerprint,
			Recipe: a.Recipe, Status: a.Status, TokenIssued: a.Token != "", Reason: a.Reason,
			CreatedAt: a.CreatedAt, DecidedAt: a.DecidedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/approvals/{id} — one row. Unlike the list, this INCLUDES the signed token once the row
// is approved, so the orchestrator that triggered the escalation can retrieve it and present it on
// its retry. (The token is a capability; in dev this endpoint is unauthenticated like the rest.)
func (s *Server) handleApprovalGet(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	a, err := s.Store.GetApproval(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errObj("no such approval: "+r.PathValue("id")))
		return
	}
	resp := struct {
		ApprovalView
		Token string `json:"token,omitempty"`
	}{
		ApprovalView: ApprovalView{
			ID: a.ID, Tool: a.Tool, Args: decodeArgs(a.ArgsJSON), Fingerprint: a.Fingerprint,
			Recipe: a.Recipe, Status: a.Status, TokenIssued: a.Token != "", Reason: a.Reason,
			CreatedAt: a.CreatedAt, DecidedAt: a.DecidedAt,
		},
	}
	if a.Status == "approved" {
		resp.Token = a.Token // only a live (unconsumed) approval yields a usable token
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/approvals/{id}/approve  — body {reason?} — mints the SIGNED release (ed25519 over the
// action fingerprint) and flips the row pending->approved. The retried tool call then releases
// through the recipe's signed_equality gate. Returns the token so the orchestrator can present it.
func (s *Server) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	if len(s.Priv) != 64 {
		writeJSON(w, http.StatusInternalServerError, errObj("no approval signing key configured"))
		return
	}
	id := r.PathValue("id")
	a, err := s.Store.GetApproval(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errObj("no such approval: "+id))
		return
	}
	if a.Status != "pending" {
		writeJSON(w, http.StatusConflict, errObj("approval is "+a.Status+", not pending"))
		return
	}
	token := egress.SignApproval(s.Priv, a.Fingerprint) // the signed release, bound to this exact action
	if err := s.Store.ApproveApproval(r.Context(), id, token, readReason(r)); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "approved", "token": token, "keyId": egress.KeyID(s.Priv.Public().(ed25519.PublicKey))})
}

// POST /api/approvals/{id}/deny — body {reason?} — rejects a pending action; the denial sticks.
func (s *Server) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DenyApproval(r.Context(), id, readReason(r)); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "denied"})
}

// readReason pulls an optional {reason} from a request body (empty on any decode miss).
func readReason(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Reason
}

// decodeArgs parses the stored args JSON back to a map (empty on error) for the dashboard.
func decodeArgs(argsJSON string) map[string]string {
	m := map[string]string{}
	if argsJSON != "" {
		_ = json.Unmarshal([]byte(argsJSON), &m)
	}
	return m
}
