package agent

import "testing"

// A bound session URL must take the HTTP transport. Routing it to the stdio path makes the harness
// fork/exec the URL as a program, which fails as "no such file or directory" — a transport mismatch
// wearing the mask of a missing binary.
func TestIsHTTPEndpoint(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{"http://localhost:8091/mcp/6f8e3bbf0fa871d689740eecb139eeeb", true},
		{"https://gate.internal/mcp/abc123", true},
		{"  http://localhost:8091/mcp/tok  ", true},
		{"stag-proxy", false},
		{"stag-proxy -recipes ./recipes", false},
		{"/usr/local/bin/stag-proxy", false},
		{"", false},
	} {
		if got := isHTTPEndpoint(tc.target); got != tc.want {
			t.Errorf("isHTTPEndpoint(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}
