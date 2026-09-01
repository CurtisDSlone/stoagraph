package serve_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
)

const brokenSrc = `recipe: broken
version: 1
rules:
  r.x:
    kind: set_membership
    set: ["a"]
steps:
  - id: p
    kind: propose
    out: v
  - id: s
    kind: sink
    in: v
    field: mcp.x.v
    sensitivity: authoritative
    rule: r.x
`

func recipeServer(t *testing.T) http.Handler {
	t.Helper()
	return (&serve.Server{Gate: proxy.Gate{Routes: proxy.Router{}}, Recipes: recipestore.Store{Dir: t.TempDir()}, Auth: &auth.Authenticator{Disabled: true}}).Handler()
}

func TestRecipeValidate(t *testing.T) {
	h := recipeServer(t)
	// good
	w := do(t, h, "POST", "/api/recipes/validate", []byte(policySrc))
	var vr recipestore.ValidateResult
	_ = json.Unmarshal(w.Body.Bytes(), &vr)
	if w.Code != 200 || !vr.Valid || len(vr.Tiers) == 0 {
		t.Fatalf("validate good: status=%d %+v", w.Code, vr)
	}
	// broken -> valid:false with an error, still 200 (validate never rejects the request)
	w = do(t, h, "POST", "/api/recipes/validate", []byte(brokenSrc))
	vr = recipestore.ValidateResult{}
	_ = json.Unmarshal(w.Body.Bytes(), &vr)
	if w.Code != 200 || vr.Valid || vr.Error == "" {
		t.Fatalf("validate broken: status=%d %+v", w.Code, vr)
	}
}

func TestRecipeCRUD(t *testing.T) {
	h := recipeServer(t)

	// save good
	w := do(t, h, "POST", "/api/recipes", []byte(policySrc))
	if w.Code != 200 {
		t.Fatalf("save good: %d %s", w.Code, w.Body.String())
	}
	// save broken -> 400, not persisted
	w = do(t, h, "POST", "/api/recipes", []byte(brokenSrc))
	if w.Code != 400 {
		t.Errorf("save broken must be 400, got %d", w.Code)
	}

	// list -> one recipe
	w = do(t, h, "GET", "/api/recipes", nil)
	var list []recipestore.ValidateResult
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != 200 || len(list) != 1 || list[0].Name != "write_note_policy" {
		t.Fatalf("list: %d %+v", w.Code, list)
	}

	// get -> src + result
	w = do(t, h, "GET", "/api/recipes/write_note_policy", nil)
	var det serve.RecipeDetail
	_ = json.Unmarshal(w.Body.Bytes(), &det)
	if w.Code != 200 || det.Src == "" || !det.Result.Valid {
		t.Fatalf("get: %d %+v", w.Code, det)
	}

	// get unknown -> 404
	if w := do(t, h, "GET", "/api/recipes/nope", nil); w.Code != 404 {
		t.Errorf("get unknown must 404, got %d", w.Code)
	}
	// traversal name -> 404 (store rejects the name)
	if w := do(t, h, "GET", "/api/recipes/..", nil); w.Code == 200 {
		t.Errorf("traversal name must not 200")
	}

	// delete -> gone
	if w := do(t, h, "DELETE", "/api/recipes/write_note_policy", nil); w.Code != 200 {
		t.Errorf("delete: %d", w.Code)
	}
	w = do(t, h, "GET", "/api/recipes", nil)
	list = nil
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("after delete list must be empty: %+v", list)
	}
}
