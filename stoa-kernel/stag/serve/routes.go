package serve

// file-kw: route endpoints tool recipe binding list put delete resolution status multi-tool

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/router"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

// kw: route view tool recipe gatearg valid error resolution
type RouteView struct {
	Tool    string `json:"tool"`
	Server  string `json:"server"` // the MCP server this tool is dispatched to
	Recipe  string `json:"recipe"`
	GateArg string `json:"gateArg"`
	// Sequenced: bound only for a recipe's `invoke` to authorize — not advertised to the agent,
	// and unreachable without a one-shot grant.
	Sequenced bool   `json:"sequenced,omitempty"`
	Valid     bool   `json:"valid"`           // does the bound recipe resolve (load + parse)?
	Error     string `json:"error,omitempty"` // why not, if invalid
}

// GET /api/routes — the tool→recipe bindings with their resolution status (a route
// whose recipe is missing/invalid is shown invalid; that tool is denied by default).
func (s *Server) handleRouteList(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, []RouteView{})
		return
	}
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	specs := make([]router.Spec, 0, len(routes))
	for _, rt := range routes {
		specs = append(specs, router.Spec{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg, Sequenced: rt.Sequenced})
	}
	resolved := router.Build(specs, s.Recipes.Get)
	// Keyed by the ADVERTISED name, because a bare tool name no longer identifies one route: the same
	// tool on two servers is two bindings, each with its own recipe and its own resolution status.
	errBy := map[string]string{}
	for _, e := range resolved.Errors {
		errBy[proxy.AdvertisedName(e.Server, e.Tool)] = e.Err
	}
	out := make([]RouteView, 0, len(routes))
	for _, rt := range routes {
		adv := proxy.AdvertisedName(rt.Server, rt.Tool)
		_, ok := resolved.Router[adv]
		out = append(out, RouteView{Tool: rt.Tool, Server: rt.Server, Recipe: rt.Recipe, GateArg: rt.GateArg, Sequenced: rt.Sequenced, Valid: ok, Error: errBy[adv]})
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/routes — {tool, server, recipe, gateArg}; upserts the binding.
//
// The SERVER is part of the route, and required. The gate must never work out which downstream a tool
// belongs to: if it did, registering an unrelated MCP server that happens to expose the same tool name
// could change — or invalidate — a route you already wrote. A route means the same thing tomorrow.
func (s *Server) handleRoutePut(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Tool      string `json:"tool"`
		Server    string `json:"server"`
		Recipe    string `json:"recipe"`
		GateArg   string `json:"gateArg"`
		Sequenced bool   `json:"sequenced"`
	}
	if json.Unmarshal(body, &req) != nil || req.Tool == "" || req.Recipe == "" {
		writeJSON(w, http.StatusBadRequest, errObj("route needs a tool, server, and recipe"))
		return
	}
	if req.Server == "" {
		writeJSON(w, http.StatusBadRequest, errObj("route needs a `server`: which MCP server serves this tool"))
		return
	}
	// The named server must exist AND expose this tool. Catching it here means the operator learns at
	// authoring time, not when an agent's call mysteriously fails.
	sv, gerr := s.Store.GetMCPServer(r.Context(), req.Server)
	if gerr != nil {
		writeJSON(w, http.StatusBadRequest, errObj("unknown MCP server: "+req.Server))
		return
	}
	decl, known := findTool(sv.Tools, req.Tool)
	if len(sv.Tools) > 0 && !known {
		writeJSON(w, http.StatusBadRequest, errObj(
			"server "+req.Server+" does not expose a tool named "+req.Tool))
		return
	}

	// An EMPTY gateArg means "this tool has no argument for the policy to judge" — the route itself is
	// the authorization, and the recipe still decides (a benign sink allows; an authoritative one can
	// still deny or escalate). That is how a zero-argument tool like `get_me` becomes routable at all.
	//
	// It is allowed ONLY when the tool genuinely takes no arguments. If the tool HAS arguments, an empty
	// gateArg would forward every one of them unjudged — the exact fail-open an omission must never buy
	// you. So we check the declared schema and refuse, naming the arguments the operator has to choose
	// from. If the tool's schema is unknown (undiscovered server), we refuse too: we cannot prove the
	// tool is argument-free, and an unprovable claim fails closed.
	if req.GateArg == "" {
		args, ok := toolArgNames(decl.InputSchema)
		switch {
		case !known || !ok:
			writeJSON(w, http.StatusBadRequest, errObj(
				"gateArg may only be empty for a tool with no arguments, and "+req.Tool+
					"'s schema is not known — connect the server so its tools are discovered, or name the argument(s) to gate"))
			return
		case len(args) > 0:
			writeJSON(w, http.StatusBadRequest, errObj(
				"tool "+req.Tool+" takes arguments ("+strings.Join(args, ", ")+
					") — name the one(s) the policy must judge in `gateArg`; an empty gateArg would forward them all unjudged"))
			return
		}
	}
	if err := s.Store.PutRoute(r.Context(), store.Route{Tool: req.Tool, Server: req.Server, Recipe: req.Recipe, GateArg: req.GateArg, Sequenced: req.Sequenced}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tool": req.Tool, "server": req.Server, "recipe": req.Recipe, "gateArg": req.GateArg, "sequenced": req.Sequenced})
}

// findTool locates a server's declaration of one tool.
func findTool(tools []store.MCPTool, name string) (store.MCPTool, bool) {
	i := slices.IndexFunc(tools, func(t store.MCPTool) bool { return t.Name == name })
	if i < 0 {
		return store.MCPTool{}, false
	}
	return tools[i], true
}

// toolArgNames reports the argument names a tool declares, from its JSON Schema. ok=false means the
// schema could not be read at all — the caller must then fail closed rather than assume "no arguments".
// A schema with no `properties` is a genuinely argument-free tool (ok=true, empty list).
// kw: tool schema properties argument names zero-arg
func toolArgNames(schema string) (names []string, ok bool) {
	if strings.TrimSpace(schema) == "" {
		return nil, false
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal([]byte(schema), &s) != nil {
		return nil, false
	}
	names = make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		names = append(names, k)
	}
	slices.Sort(names) // deterministic error message
	return names, true
}

// DELETE /api/routes/{server}/{tool}
//
// Both halves of the key, because a route is (server, tool): deleting `search_code` on `github` must
// leave `search_code` on `local` alone, and a tool name by itself cannot say which was meant.
func (s *Server) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusNotImplemented, errObj("no config store"))
		return
	}
	tool, server := r.PathValue("tool"), r.PathValue("server")
	if tool == "" || server == "" {
		writeJSON(w, http.StatusBadRequest, errObj("delete needs both a server and a tool"))
		return
	}
	if err := s.Store.DeleteRoute(r.Context(), tool, server); err != nil {
		writeJSON(w, http.StatusInternalServerError, errObj(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": proxy.AdvertisedName(server, tool)})
}
