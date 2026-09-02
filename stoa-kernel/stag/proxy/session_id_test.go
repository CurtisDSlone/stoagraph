package proxy

import "testing"

// The audit id must never be the token. The token is the agent's bearer credential; an audit log is
// read by more parties than may hold it, so a log that echoed tokens would hand out session access.
func TestSessionIDNeverEchoesTheToken(t *testing.T) {
	const tok = "6f8e3bbf0fa871d689740eecb139eeeb"
	id := SessionID(tok)
	if id == tok {
		t.Fatal("SessionID returned the token verbatim — a bearer credential must never reach the log")
	}
	if len(id) != 32 { // 16 bytes hex
		t.Errorf("SessionID length = %d, want 32", len(id))
	}
}

// Stable, so an auditor can group every decision a session made.
func TestSessionIDIsStableAndDistinct(t *testing.T) {
	a1, a2 := SessionID("token-a"), SessionID("token-a")
	b := SessionID("token-b")
	if a1 != a2 {
		t.Errorf("SessionID not stable: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Error("distinct tokens produced the same session id")
	}
}

// A gate outside a bound session (the control plane's preview gate) records no session.
func TestSessionIDEmptyForNoToken(t *testing.T) {
	if got := SessionID(""); got != "" {
		t.Errorf("SessionID(\"\") = %q, want empty", got)
	}
}
