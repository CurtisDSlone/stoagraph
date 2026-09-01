package serve_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

func mcpServer(t *testing.T, discover func(ctx context.Context, srv store.MCPServer) ([]store.MCPTool, error)) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv := &serve.Server{
		Gate:     proxy.Gate{Routes: proxy.Router{}},
		Recipes:  recipestore.Store{Dir: t.TempDir()},
		Store:    st,
		Discover: discover,
		Auth:     &auth.Authenticator{Disabled: true},
	}
	return srv.Handler(), st
}

func TestMCPServerAddWithDiscovery(t *testing.T) {
	discover := func(ctx context.Context, srv store.MCPServer) ([]store.MCPTool, error) {
		return []store.MCPTool{{Name: "read_file"}, {Name: "write_file"}}, nil
	}
	h, _ := mcpServer(t, discover)

	w := do(t, h, "POST", "/api/mcp-servers", []byte(`{"name":"fs","transport":"stdio","target":"npx server-fs"}`))
	if w.Code != 200 {
		t.Fatalf("add server: %d %s", w.Code, w.Body.String())
	}
	var v serve.MCPServerView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.Name != "fs" || len(v.Tools) != 2 || v.DiscoverError != "" {
		t.Fatalf("discovered server: %+v", v)
	}

	// list shows it with its tools
	w = do(t, h, "GET", "/api/mcp-servers", nil)
	var list []serve.MCPServerView
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || len(list[0].Tools) != 2 {
		t.Fatalf("list: %+v", list)
	}

	// bad transport -> 400
	if w := do(t, h, "POST", "/api/mcp-servers", []byte(`{"name":"x","transport":"smtp","target":"y"}`)); w.Code != 400 {
		t.Errorf("bad transport must 400, got %d", w.Code)
	}

	// delete
	if w := do(t, h, "DELETE", "/api/mcp-servers/fs", nil); w.Code != 200 {
		t.Errorf("delete: %d", w.Code)
	}
	w = do(t, h, "GET", "/api/mcp-servers", nil)
	list = nil
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("after delete: %+v", list)
	}
}

func TestMCPServerUnreachableStoredWithError(t *testing.T) {
	discover := func(ctx context.Context, srv store.MCPServer) ([]store.MCPTool, error) {
		return nil, errors.New("connection refused")
	}
	h, _ := mcpServer(t, discover)

	w := do(t, h, "POST", "/api/mcp-servers", []byte(`{"name":"down","transport":"http","target":"http://127.0.0.1:1"}`))
	if w.Code != 200 {
		t.Fatalf("unreachable server should still store: %d", w.Code)
	}
	var v serve.MCPServerView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.DiscoverError == "" || len(v.Tools) != 0 {
		t.Errorf("unreachable: expected discoverError + no tools, got %+v", v)
	}
	// but it is stored, so it lists
	w = do(t, h, "GET", "/api/mcp-servers", nil)
	var list []serve.MCPServerView
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Name != "down" {
		t.Errorf("stored despite unreachable: %+v", list)
	}
}
