package serve

// file-kw: recipe authoring endpoints validate list get save delete admin console

import (
	"io"
	"net/http"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
)

// kw: recipe detail name src validate result
type RecipeDetail struct {
	Name   string                     `json:"name"`
	Src    string                     `json:"src"`
	Result recipestore.ValidateResult `json:"result"`
}

// POST /api/recipes/validate — body is raw recipe YAML; returns the linter result
// (valid, error, warnings, tier preview) WITHOUT persisting. The live-editor path.
func (s *Server) handleRecipeValidate(w http.ResponseWriter, r *http.Request) {
	src, _ := io.ReadAll(r.Body)
	writeJSON(w, http.StatusOK, s.Recipes.Validate(src)) // composes goto_recipe against the store
}

// GET /api/recipes — a validated summary of every stored recipe.
func (s *Server) handleRecipeList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Recipes.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	if list == nil {
		list = []recipestore.ValidateResult{}
	}
	writeJSON(w, http.StatusOK, list)
}

// POST /api/recipes — body is raw recipe YAML; validates then persists. An invalid
// recipe is 400 with the ValidateResult (error + no tiers); it is never saved.
func (s *Server) handleRecipeSave(w http.ResponseWriter, r *http.Request) {
	src, _ := io.ReadAll(r.Body)
	vr, err := s.Recipes.Save(src)
	if !vr.Valid {
		writeJSON(w, http.StatusBadRequest, vr) // fail closed: the linter refused it
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error())) // valid but write failed
		return
	}
	writeJSON(w, http.StatusOK, vr)
}

// GET /api/recipes/{name} — the raw YAML + its current validation result.
func (s *Server) handleRecipeGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	src, err := s.Recipes.Get(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, RecipeDetail{Name: name, Src: string(src), Result: s.Recipes.Validate(src)})
}

// DELETE /api/recipes/{name}
func (s *Server) handleRecipeDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Recipes.Delete(name); err != nil {
		writeJSON(w, http.StatusNotFound, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}
