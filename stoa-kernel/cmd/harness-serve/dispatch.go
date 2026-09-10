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
	emitpkg "github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
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
	emit(agent.Event{Kind: "dispatch", Tool: dec.RecipeID,
		Result: fmt.Sprintf("routed to %s via %s (confidence %s)", dec.RecipeID, via, dec.Confidence)})

	s.governedRun(ctx, dec, req.Event, req.Model, req.System, req.MaxTurns, emit,
		emitpkg.NewOrchestrationContext(eventID(req.Event)))
}

// governedRun is the "run a governed agent for a resolved event" core, shared by the SSE console
// dispatch (above) and the webhook front door (ingress.go). Given a Decision (recipe/toolset/context
// already chosen), it binds a session on the stag-proxy daemon, connects the agent loop, reads the
// session's UNTRUSTED context from the gate, and runs the model<->gate loop. Every proposed tool call
// is gated; a misroute cannot breach. emit streams the transcript (SSE downstream, or a log for the
// async webhook path).
func (s *Server) governedRun(ctx context.Context, dec dispatch.Decision, event map[string]any, modelName, system string, maxTurns int, emit func(agent.Event), oc emitpkg.OrchestrationContext) {
	stag := dispatch.StagClient{BaseURL: s.approvals, Token: s.stagToken}
	// A session's toolset AND its READ-channel providers come entirely from the recipe itself now —
	// the event map names only WHICH recipe governs. RoutesForSession resolves every route the
	// recipe governs directly PLUS the routes for every sub-tool its own invoke/await steps
	// authorize (a sequenced sub-tool is deliberately routed to its OWN separate recipe, never the
	// recipe that invokes it — RoutesForRecipe alone would never reach it, which is the gap an
	// invoke-only trigger recipe used to fall into: every sub-call denied "no recipe for tool",
	// and nothing the agent could act on). ProviderNamesForSession mirrors this for the READ
	// channel: the trigger recipe's own providers: allowlist, unioned with each distinct
	// sub-recipe's. Nothing is unioned in from a separate event-map-declared list anymore.
	var routes []dispatch.RouteSpec
	var providers []dispatch.ProviderSpec
	var err error
	if dec.RecipeID != "" {
		routes, err = stag.RoutesForSession(dec.RecipeID)
		if err != nil {
			emit(agent.Event{Kind: "error", Text: "routes for session: " + err.Error()})
			return
		}
		names, nerr := stag.ProviderNamesForSession(dec.RecipeID, routes)
		if nerr != nil {
			emit(agent.Event{Kind: "dispatch", Result: "recipe providers unavailable, proceeding without READ channel: " + nerr.Error()})
		} else if len(names) > 0 {
			var perr error
			providers, perr = stag.ProvidersFor(names)
			if perr != nil {
				emit(agent.Event{Kind: "dispatch", Result: "context providers unavailable, proceeding without READ channel: " + perr.Error()})
				providers = nil
			}
		}
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

	// Accumulate the recipe's emit sinks as the transcript goes by. The sinks ride
	// `verdict` events (agent.Event.Sinks); the agent itself never reads them.
	var collector emitpkg.SinkCollector
	tap := func(e agent.Event) {
		if len(e.Sinks) > 0 {
			collector.Add(e.Sinks)
		}
		emit(e)
	}
	agent.Run(ctx, proposer, sess, maxTurns, agent.NewApprovalConfig(s.approvals, s.stagToken), tap)

	s.runEmits(ctx, collector.All(), modelName, system, maxTurns, emit, oc)
}

// runEmits is the orchestration hop: an emitted event is re-dispatched through the SAME
// front door an external event uses — LoadEventMap, Dispatcher.Dispatch, then governedRun.
//
// It re-routes rather than calling the next recipe directly, and that is the whole safety
// argument. The emitted event carries no authority from the recipe that emitted it: the
// next session is bound to the NEXT recipe's own routes, and every call it proposes is
// re-gated against that recipe. A chain cannot launder an action by emitting toward it.
//
// The event map is re-read per hop deliberately. A hop is a fresh routing decision, and an
// operator who edits the map mid-chain means it — a cached map would let a revoked route
// keep serving for the life of a chain.
func (s *Server) runEmits(ctx context.Context, sinks []map[string]any, modelName, system string, maxTurns int, emit func(agent.Event), oc emitpkg.OrchestrationContext) {
	if len(sinks) == 0 {
		return
	}
	// Slot values ride the gate's own sink metadata for emit fields (mcpgate.withSinks),
	// so nil here means "no harness override" — EmitFromMetadata reads the gate's value.
	summary, err := emitpkg.ProcessEmitsAfterRun(ctx, sinks, nil, oc,
		func(ctx context.Context, event map[string]any, next emitpkg.OrchestrationContext) (bool, error) {
			emap, err := dispatch.LoadEventMap(s.eventMap)
			if err != nil {
				return false, err
			}
			stagc := dispatch.StagClient{BaseURL: s.approvals, Token: s.stagToken}
			dec, err := dispatch.Dispatcher{Map: emap, Catalog: stagc.Catalog}.Dispatch(ctx, dispatch.Event(event))
			if err != nil {
				return false, err
			}
			if !dec.Dispatched() {
				return false, nil // nothing listens for this kind; the chain ends here
			}
			emit(agent.Event{Kind: "dispatch", Tool: dec.RecipeID, Result: fmt.Sprintf(
				"emit → %v routed to %s (depth %d/%d)", event["kind"], dec.RecipeID, next.EmitDepth, emitpkg.MaxEmitDepth)})
			s.governedRun(ctx, dec, event, modelName, system, maxTurns, emit, next)
			return true, nil
		})
	if err != nil {
		emit(agent.Event{Kind: "error", Text: "emit processing: " + err.Error()})
		return
	}
	if summary.Blocked {
		emit(agent.Event{Kind: "dispatch", Result: fmt.Sprintf(
			"emit chain stopped: %s (path: %s)", summary.BlockReason, strings.Join(oc.EmissionPath, " → "))})
		return
	}
	if summary.Invalid > 0 {
		emit(agent.Event{Kind: "dispatch", Result: fmt.Sprintf(
			"%d of %d emit(s) not dispatched", summary.Invalid, summary.Total)})
	}
}

// eventID names an event for the orchestration chain. The ingress id when the event
// carries one, else a marker — the id is for AUDIT LEGIBILITY (which chain is this),
// never for authority, so an unnamed event is not an error.
func eventID(event map[string]any) string {
	for _, k := range []string{"id", "event_id", "_id"} {
		if v, ok := event[k].(string); ok && v != "" {
			return v
		}
	}
	return "evt"
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
