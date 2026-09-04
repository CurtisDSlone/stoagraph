package main

// file-kw: dispatch ingress event->recipe->session->agent turnkey governed-agent sse stream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/agent"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/bind"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// getEventMap returns the raw event map JSON (an empty array when the file is absent) for the editor.
func (s *Server) getEventMap(w http.ResponseWriter, _ *http.Request) {
	b, err := os.ReadFile(s.eventMap)
	if os.IsNotExist(err) || len(b) == 0 {
		writeJSON(w, http.StatusOK, []dispatch.Definition{})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// putEventMap validates + persists an edited event map (a JSON array of definitions).
func (s *Server) putEventMap(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m dispatch.EventMap
	if json.Unmarshal(body, &m) != nil {
		writeErr(w, http.StatusBadRequest, "invalid event map: expected a JSON array of {id, match, recipe} definitions")
		return
	}
	pretty, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(s.eventMap, append(pretty, '\n'), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(m)})
}

const defaultDispatchSystem = "You are an operations agent. An event has arrived. Handle it by " +
	"CALLING the available tools directly — do not just describe. Only the tools this session " +
	"exposes are available to you."

// dispatch is the turnkey ingress (Planning/25): an EVENT arrives, the dispatcher routes it to a
// recipe (deterministic event map first, then the dispatch model + Gate), binds a session on the
// stag-proxy daemon for that recipe, and runs the agent loop against the event — the whole
// "event → governed agent" path, streamed as SSE. The model never chooses its own recipe, and a
// misroute cannot breach (stag enforces whatever recipe the session was bound to).
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Event         map[string]any `json:"event"`
		DispatchModel string         `json:"dispatchModel"`
		Model         string         `json:"model"`
		System        string         `json:"system"`
		MaxTurns      int            `json:"maxTurns"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Event) == 0 {
		writeErr(w, 400, "need an event object")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	emit := func(e agent.Event) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	ctx := r.Context()

	// 1. resolve event -> recipe.
	var router dispatch.Router
	if req.DispatchModel != "" {
		m, ok, err := s.models.Get(req.DispatchModel)
		if err != nil || !ok {
			emit(agent.Event{Kind: "error", Text: "dispatch model not found: " + req.DispatchModel})
			return
		}
		router, err = dispatch.NewRouter(m)
		if err != nil {
			emit(agent.Event{Kind: "error", Text: err.Error()})
			return
		}
	}
	stag := dispatch.StagClient{BaseURL: s.approvals, Token: s.stagToken} // the `dispatch` role
	emap, err := dispatch.LoadEventMap(s.eventMap)
	if err != nil {
		emit(agent.Event{Kind: "error", Text: err.Error()})
		return
	}
	dec, err := dispatch.Dispatcher{Map: emap, Router: router, Catalog: stag.Catalog}.Dispatch(ctx, dispatch.Event(req.Event))
	if err != nil {
		emit(agent.Event{Kind: "error", Text: "dispatch: " + err.Error()})
		return
	}
	if !dec.Dispatched() {
		emit(agent.Event{Kind: "dispatch", Result: "no recipe routed for this event (fail closed)"})
		emit(agent.Event{Kind: "done"})
		return
	}
	via := dec.Mode
	if dec.Definition != "" {
		via += " · " + dec.Definition
	} else if dec.Router != "" {
		via += " · " + dec.Router
	}
	target := dec.RecipeID
	if len(dec.Tools) > 0 {
		target = fmt.Sprintf("toolset [%s]", strings.Join(dec.Tools, ", "))
	}
	emit(agent.Event{Kind: "dispatch", Tool: dec.RecipeID,
		Result: fmt.Sprintf("routed to %s via %s (confidence %s)", target, via, dec.Confidence)})

	s.governedRun(ctx, dec, req.Event, req.Model, req.System, req.MaxTurns, emit)
}

// governedRun is the "run a governed agent for a resolved event" core, shared by the SSE console
// dispatch (above) and the webhook front door (ingress.go). Given a Decision (recipe/toolset/context
// already chosen), it binds a session on the stag-proxy daemon, connects the agent loop, reads the
// session's UNTRUSTED context from the gate, and runs the model<->gate loop. Every proposed tool call
// is gated; a misroute cannot breach. emit streams the transcript (SSE downstream, or a log for the
// async webhook path).
func (s *Server) governedRun(ctx context.Context, dec dispatch.Decision, event map[string]any, modelName, system string, maxTurns int, emit func(agent.Event)) {
	stag := dispatch.StagClient{BaseURL: s.approvals, Token: s.stagToken}
	// Union both route sources rather than picking one: an event-map entry naming BOTH a recipe and
	// an explicit tools list wants both bound — the recipe's own trigger tool (whose invoke/await
	// steps are the only place a multi-step arc is actually enforced) alongside any individually
	// listed diagnostic tools. Picking only one, as this used to, meant a `tools:` list silently
	// dropped dec.RecipeID and the recipe's trigger tool was never reachable — so its invoke/await
	// enforcement never ran in the autonomous dispatch path, for any scenario that names `tools`.
	var routes []dispatch.RouteSpec
	var err error
	if dec.RecipeID != "" {
		routes, err = stag.RoutesForRecipe(dec.RecipeID)
		if err != nil {
			emit(agent.Event{Kind: "error", Text: "routes for session: " + err.Error()})
			return
		}
	}
	if len(dec.Tools) > 0 {
		extra, terr := stag.RoutesForTools(dec.Tools)
		if terr != nil {
			emit(agent.Event{Kind: "error", Text: "routes for session: " + terr.Error()})
			return
		}
		routes = mergeRouteSpecs(routes, extra)
	}
	providers, perr := stag.ProvidersFor(dec.Context)
	if perr != nil {
		emit(agent.Event{Kind: "dispatch", Result: "context providers unavailable, proceeding without READ channel: " + perr.Error()})
		providers = nil
	}
	endpoint, token, err := dispatch.Binder{DaemonURL: s.daemon, Token: s.stagToken}.Bind(ctx, routes, providers)
	if err != nil {
		emit(agent.Event{Kind: "error", Text: "bind session: " + err.Error()})
		return
	}
	bound := fmt.Sprintf("session bound (token %s…) — %d route(s)", token[:min(8, len(token))], len(routes))
	if len(providers) > 0 {
		names := make([]string, len(providers))
		for i, p := range providers {
			names[i] = p.Name
		}
		bound += fmt.Sprintf(" + %d context provider(s) [%s]", len(providers), strings.Join(names, ", "))
	}
	emit(agent.Event{Kind: "dispatch", Result: bound + " on the daemon"})

	sess, tools, err := agent.ConnectHTTP(ctx, endpoint)
	if err != nil {
		emit(agent.Event{Kind: "error", Text: "connect daemon: " + err.Error()})
		return
	}
	defer sess.Close()
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	emit(agent.Event{Kind: "text", Text: fmt.Sprintf("agent session — gated tool(s): %v", names)})

	m, ok, err := s.models.Get(modelName)
	if err != nil || !ok {
		emit(agent.Event{Kind: "error", Text: "proposer model not found: " + modelName})
		return
	}
	if system == "" {
		system = defaultDispatchSystem
	}
	eventJSON := eventInput(event)
	docs := readGateContext(ctx, sess, eventJSON)
	if len(docs) > 0 {
		srcs := make([]string, len(docs))
		for i, d := range docs {
			srcs[i] = d.Source
		}
		emit(agent.Event{Kind: "dispatch", Result: fmt.Sprintf("context: %d untrusted item(s) read from the gate [%s]", len(docs), strings.Join(srcs, ", "))})
	}
	breq := bind.Assemble(system, eventJSON, docs)
	proposer, err := buildModel(m, breq.System, breq.Input, tools)
	if err != nil {
		emit(agent.Event{Kind: "error", Text: err.Error()})
		return
	}
	if maxTurns <= 0 {
		maxTurns = 6
	}
	agent.Run(ctx, proposer, sess, maxTurns, agent.NewApprovalConfig(s.approvals, s.stagToken), emit)
}

// mergeRouteSpecs unions two route sets, deduping by (server, tool) so the same downstream call is
// never bound twice. base wins on conflict — it holds the recipe's own routes, which include its
// sequenced/invoke-only tools; extra holds the explicitly-listed tools from the event map. Keeping
// base first means a recipe's own binding for a tool is never silently overridden by a same-named
// entry in an event map's `tools` list.
func mergeRouteSpecs(base, extra []dispatch.RouteSpec) []dispatch.RouteSpec {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]dispatch.RouteSpec, 0, len(base)+len(extra))
	for _, r := range base {
		key := r.Server + "\x00" + r.Tool
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	for _, r := range extra {
		key := r.Server + "\x00" + r.Tool
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

// eventInput renders the event as compact-ish JSON — the untrusted "ticket". bind.Assemble adds the
// trust-position framing, so no prefix here.
func eventInput(e map[string]any) string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b)
}

// contextURIPrefix is the READ-channel namespace the gate serves resource templates under.
const contextURIPrefix = "stag://context/"

// readGateContext reads the session's context FROM THE GATE (Planning/30): it lists the
// stag://context/* resource templates the session was bound to and reads each with ?q=<event>. The
// gate Gathers the providers, stamps every item untrusted at origin, and records the crossing — so
// the harness trusts the CHANNEL, not the content. Best-effort: any error yields no context (the READ
// channel is enrichment, never required). The untrusted text goes to bind's Input slot.
func readGateContext(ctx context.Context, sess *mcp.ClientSession, query string) []bind.Doc {
	tmpls, err := sess.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{})
	if err != nil || tmpls == nil {
		return nil
	}
	var docs []bind.Doc
	for _, t := range tmpls.ResourceTemplates {
		if !strings.HasPrefix(t.URITemplate, contextURIPrefix) {
			continue
		}
		base := strings.TrimSuffix(t.URITemplate, "{?q}")
		// The template (RFC 6570 {?q}) matches PERCENT-encoding only; url.QueryEscape emits "+" for
		// spaces, which the matcher rejects (→ "resource not found"). Encode spaces as %20.
		res, err := sess.ReadResource(ctx, &mcp.ReadResourceParams{URI: base + "?q=" + strings.ReplaceAll(url.QueryEscape(query), "+", "%20")})
		if err != nil || res == nil {
			continue
		}
		for _, c := range res.Contents {
			if strings.TrimSpace(c.Text) == "" {
				continue
			}
			docs = append(docs, bind.Doc{Source: t.Name, Text: c.Text})
		}
	}
	return docs
}
