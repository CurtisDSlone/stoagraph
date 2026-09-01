package main

// file-kw: webhook ingress receiver hmac verify record chained lane-1 dispatch front-door

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/agent"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
)

// webhook is the event front door (Planning/32, I2): an external source POSTs a signed delivery, the
// generic HMAC adapter verifies the channel and normalizes it to an Envelope, the arrival is recorded
// to the hash-chained ingress log REGARDLESS of disposition, and an attributed + matched event is
// resolved to a recipe by the deterministic event map (lane 1 — no model on the front door). The
// resolved run is handed to the same governed pipeline the console's /api/dispatch uses.
//
// This handler NEVER enforces and NEVER fires an actuator (Planning/13): it verifies its channel,
// records, and routes. A misroute or a forged event is contained downstream by the gate.
//
// Disposition, always recorded:
//   - "dropped:shape"        the body was unparseable/oversize (adapter error) -> 400
//   - "dropped:unattributed" a definition matched but requires attribution the event lacks -> 202
//   - "dropped:no-route"     nothing in the event map matched -> 202
//   - "dispatched:<recipe>"  an attributed (or attribution-not-required) match -> 200
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	if s.ingressChain == nil {
		writeErr(w, http.StatusServiceUnavailable, "ingress not configured (no --ingress-log)")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, ingress.MaxBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	// The adapter for this endpoint. v1: one generic HMAC source; named adapters key off the {source}
	// path segment in a later slice.
	adapter := ingress.GenericHMAC{Source: r.PathValue("source"), Secret: s.ingressSecret}

	env, err := adapter.Accept(headerMap(r), body)
	if err != nil {
		// Shape failure: we cannot even form an envelope. Record a minimal dropped leaf and refuse.
		_ = s.ingressChain.Append(ingress.Record{
			Source: adapter.Name(), Disposition: "dropped:shape",
		})
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve deterministically (event map only; no model on the front door). The event the dispatcher
	// sees is the payload, with the envelope's source/type overlaid when the payload does not carry
	// them — so a definition can match on either.
	event := payloadEvent(env)
	emap, merr := dispatch.LoadEventMap(s.eventMap)
	if merr != nil {
		writeErr(w, http.StatusInternalServerError, merr.Error())
		return
	}
	def, matched := emap.Match(event)

	disposition := "dropped:no-route"
	status := http.StatusAccepted
	switch {
	case matched && def.RequireAttribution && !env.Attributed:
		// The governing rule: an unattributed event may not be dispatched directly. (Lane 2 —
		// validation workflow — is future; today it is refused and recorded.)
		disposition = "dropped:unattributed"
	case matched:
		disposition = "dispatched:" + def.Recipe
		status = http.StatusOK
		// RUN the governed agent loop for this event (Planning/32 lane 1, end to end). A webhook sender
		// does not wait for an incident to be worked, so the run is fire-and-forget: launched in the
		// background, its transcript to the log, its actions gated + recorded in the gate's signed
		// chains. runEvent is set only when an ingress model is configured (else the front door
		// resolves + records but does not execute — resolve-only).
		if s.runEvent != nil {
			dec := dispatch.Decision{
				RecipeID: def.Recipe, Tools: def.Tools, Context: def.Context,
				Confidence: "high", Mode: "deterministic", Definition: def.ID,
			}
			go s.runEvent(dec, event, env)
		}
	}
	_ = s.ingressChain.Append(ingress.RecordOf(env, disposition))

	writeJSON(w, status, map[string]any{
		"id": env.ID, "source": env.Source, "type": env.Type,
		"attributed": env.Attributed, "disposition": disposition,
		"recipe": routedRecipe(matched, def, disposition),
	})
}

// runIngressEvent runs the governed agent loop for a webhook-dispatched event, in the background. The
// transcript is logged (prefixed with the event id) rather than streamed — a webhook has no client to
// stream to; the enforcement record is the gate's signed chains, not this log.
func (s *Server) runIngressEvent(dec dispatch.Decision, event dispatch.Event, env ingress.Envelope) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tag := env.Source + "/" + env.ID
	log.Printf("ingress[%s]: dispatched to %q — running governed agent", tag, dec.RecipeID)
	s.governedRun(ctx, dec, map[string]any(event), s.ingressModel, "", 0, func(e agent.Event) {
		switch e.Kind {
		case "propose":
			log.Printf("ingress[%s]: PROPOSE %s(%s)", tag, e.Tool, e.Args)
		case "verdict":
			log.Printf("ingress[%s]:   gate %s %s -> %s", tag, verdictWord(e.Allowed), e.Tool, e.Result)
		case "text": // the advertised gated-tool list (tools/list) + other session narration
			log.Printf("ingress[%s]: %s", tag, e.Text)
		case "dispatch": // session bind + untrusted-context reads
			log.Printf("ingress[%s]: %s", tag, e.Result)
		case "error":
			log.Printf("ingress[%s]: error: %s", tag, e.Text)
		case "done":
			log.Printf("ingress[%s]: done. %s", tag, e.Text)
		}
	})
}

func verdictWord(allowed bool) string {
	if allowed {
		return "ALLOWED"
	}
	return "DENIED/HELD"
}

// payloadEvent turns an envelope into the dispatcher's Event view: the JSON payload as a map, with
// the envelope source/type overlaid only when the payload does not already set them (never clobber
// the source's own fields).
func payloadEvent(env ingress.Envelope) dispatch.Event {
	m := map[string]any{}
	_ = json.Unmarshal(env.Payload, &m) // adapter already validated it parses; a failure yields {}
	if _, ok := m["source"]; !ok && env.Source != "" {
		m["source"] = env.Source
	}
	if _, ok := m["type"]; !ok && env.Type != "" {
		m["type"] = env.Type
	}
	return dispatch.Event(m)
}

func routedRecipe(matched bool, def dispatch.Definition, disposition string) string {
	if matched && disposition[:len("dispatched")] == "dispatched" {
		return def.Recipe
	}
	return ""
}

func headerMap(r *http.Request) map[string]string {
	h := make(map[string]string, len(r.Header))
	for k := range r.Header {
		h[k] = r.Header.Get(k)
	}
	return h
}
