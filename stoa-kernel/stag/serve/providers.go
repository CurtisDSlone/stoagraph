package serve

// file-kw: context provider endpoints read channel list put delete adapters config

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// kw: provider view name kind config enabled
type ProviderView struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Config  string `json:"config"`
	Enabled bool   `json:"enabled"`
}

// GET /api/providers — the configured context providers (the read channel).
func (s *Server) handleProviderList(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, []ProviderView{})
		return
	}
	ps, err := s.Store.ListProviders(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	out := make([]ProviderView, 0, len(ps))
	for _, p := range ps {
		out = append(out, ProviderView{Name: p.Name, Kind: p.Kind, Config: p.Config, Enabled: p.Enabled})
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/providers — {name, kind, config, enabled}; upserts a provider config.
func (s *Server) handleProviderPut(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Config  string `json:"config"`
		Enabled *bool  `json:"enabled"`
	}
	if json.Unmarshal(body, &req) != nil || req.Name == "" || req.Kind == "" {
		writeJSON(w, http.StatusBadRequest, errObj("provider needs a name and kind"))
		return
	}
	p := store.ContextProvider{Name: req.Name, Kind: req.Kind, Config: req.Config, Enabled: req.Enabled == nil || *req.Enabled}
	if err := s.Store.PutProvider(r.Context(), p); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, ProviderView{Name: p.Name, Kind: p.Kind, Config: p.Config, Enabled: p.Enabled})
}

// DELETE /api/providers/{name}
func (s *Server) handleProviderDelete(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	if err := s.Store.DeleteProvider(r.Context(), r.PathValue("name")); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("name")})
}
