package mcpgate_test

// kw-test: query-param auth appends the key to the runtime endpoint, not the stored target

import (
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestQuerySchemeAppendsKeyToEndpoint(t *testing.T) {
	tr, err := mcpgate.TransportFor("http", "https://api.example.com/mcp?v=1",
		mcpgate.Auth{Scheme: "query", Header: "apikey", Credential: "SECRET123"})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := tr.(*mcp.StreamableClientTransport)
	if !ok {
		t.Fatalf("expected *mcp.StreamableClientTransport, got %T", tr)
	}
	if !strings.Contains(st.Endpoint, "apikey=SECRET123") {
		t.Fatalf("api key not appended to endpoint: %s", st.Endpoint)
	}
	if !strings.Contains(st.Endpoint, "v=1") {
		t.Fatalf("existing query param dropped: %s", st.Endpoint)
	}
}

func TestQuerySchemeRequiresParamName(t *testing.T) {
	if _, err := mcpgate.TransportFor("http", "https://x/mcp", mcpgate.Auth{Scheme: "query", Credential: "k"}); err == nil {
		t.Fatal("expected error when query param name is missing")
	}
}

func TestQuerySchemeRequiresCredential(t *testing.T) {
	if _, err := mcpgate.TransportFor("http", "https://x/mcp", mcpgate.Auth{Scheme: "query", Header: "apikey"}); err == nil {
		t.Fatal("expected error when credential is empty")
	}
}
