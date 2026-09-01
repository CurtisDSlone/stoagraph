package proxy_test

// kw-test: advertised tool names round-trip losslessly; server names that would make them ambiguous
// or illegal for a model tool-use API are rejected at the door

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// The advertised name must survive a round trip EXACTLY, including when the downstream's own tool name
// contains the separator. Cutting at the FIRST "__" is what makes that true, and it is only sound
// because ValidServerName forbids "__" in a server name.
func TestAdvertisedNameRoundTrips(t *testing.T) {
	for _, c := range []struct{ server, tool string }{
		{"github", "search_code"},
		{"local-tools", "read_file"},
		{"a", "b"},
		{"srv", "foo__bar"},   // the TOOL contains the separator — still unambiguous
		{"my_server", "list"}, // a single underscore in the server is fine
	} {
		adv := proxy.AdvertisedName(c.server, c.tool)
		gotSrv, gotTool, ok := proxy.SplitAdvertised(adv)
		if !ok {
			t.Fatalf("SplitAdvertised(%q) not ok", adv)
		}
		if gotSrv != c.server || gotTool != c.tool {
			t.Errorf("round trip %q: got (%q, %q), want (%q, %q)", adv, gotSrv, gotTool, c.server, c.tool)
		}
	}
}

// A name with no separator is not an advertised name. Fail closed rather than guessing a server.
func TestSplitAdvertisedRejectsBareNames(t *testing.T) {
	for _, bad := range []string{"search_code", "", "__", "__tool", "server__"} {
		if _, _, ok := proxy.SplitAdvertised(bad); ok {
			t.Errorf("SplitAdvertised(%q) must not resolve — there is no server to dispatch to", bad)
		}
	}
}

// The server name becomes half of a tool name handed to a model, so it must be legal there
// (^[a-zA-Z0-9_-]+$) and must not contain the separator (which would make the split ambiguous).
func TestValidServerName(t *testing.T) {
	valid := []string{"github", "local-tools", "my_server", "srv1", "A-b_9"}
	invalid := []string{
		"",            // nothing to prefix with
		"a__b",        // contains the separator -> ambiguous split
		"my server",   // space: rejected by the provider tool-use APIs
		"my.server",   // dot: rejected by the provider tool-use APIs
		"srv/1",       // slash
		"sérver",      // non-ascii
		"tools:local", // colon
	}
	for _, s := range valid {
		if !proxy.ValidServerName(s) {
			t.Errorf("ValidServerName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if proxy.ValidServerName(s) {
			t.Errorf("ValidServerName(%q) = true, want false", s)
		}
	}
}

// Every advertised name built from a VALID server name must itself be a legal model tool name —
// otherwise the orchestrator's tool-use call is rejected by the provider and the tool is unusable.
func TestAdvertisedNameIsModelLegal(t *testing.T) {
	legal := func(s string) bool {
		for _, r := range s {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			default:
				return false
			}
		}
		return s != ""
	}
	for _, c := range []struct{ server, tool string }{
		{"github", "search_code"},
		{"local-tools", "read_file"},
		{"my_server", "get-thing"},
	} {
		if !proxy.ValidServerName(c.server) {
			t.Fatalf("fixture server %q should be valid", c.server)
		}
		if adv := proxy.AdvertisedName(c.server, c.tool); !legal(adv) {
			t.Errorf("advertised name %q is not a legal model tool name (^[a-zA-Z0-9_-]+$)", adv)
		}
	}
}
