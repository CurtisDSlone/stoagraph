package main

// file-kw: webhook ingress receiver hmac verify record chained lane-1 dispatch front-door

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/agent"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	emitpkg "github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/emit"
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
	case matched && !s.allowUnattributed && !env.Attributed:
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
				RecipeID:   def.Recipe,
				Confidence: "high", Mode: "deterministic", Definition: def.ID,
			}
			// SINGLE-FLIGHT first: if this recipe is already working, a second event asking for
			// the same policy is duplicate work, not more work. Checked before the cap so a
			// duplicate does not consume a slot a genuinely different incident needs.
			if !s.claimRecipe(def.Recipe) {
				disposition = "dropped:already-running"
				log.Printf("ingress[%s/%s]: %s already running — collapsed (source %s)",
					env.Source, env.ID, def.Recipe, env.Source)
			} else if s.acquireRun() {
				// Reserve an in-flight slot BEFORE launching. A full cap sheds the run rather than
				// queueing it: the sender is told (disposition), the ingress chain records it, and the
				// operator can see the cap biting. A silently queued burst looks identical to a healthy
				// system right up until it is not.
				// Counted here, not in acquireRun/releaseRun: releaseRun tolerates an unpaired call
				// by design, a WaitGroup does not. This is the only place a governed run is launched,
				// so it is the one place shutdown needs to know about.
				s.runs.Add(1)
				go func() {
					defer s.runs.Done()
					defer s.releaseRun() // deferred so a panicking run cannot leak its slot
					defer s.releaseRecipe(def.Recipe)
					// Registered LAST so it runs FIRST: a panic in one governed run must not take the
					// process, every other in-flight run, and every bound MCP session down with it.
					// Contain it, log it against the event that caused it, and let the deferreds above
					// return the slot and the claim exactly as they would for a run that returned.
					defer func() {
						if r := recover(); r != nil {
							log.Printf("ingress[%s/%s]: run of %s PANICKED: %v\n%s",
								env.Source, env.ID, def.Recipe, r, debug.Stack())
						}
					}()
					s.runEvent(dec, event, env)
				}()
			} else {
				s.releaseRecipe(def.Recipe) // shed at the cap: the claim was never used
				disposition = "dropped:at-capacity"
				status = http.StatusAccepted
				log.Printf("ingress[%s/%s]: at capacity (%d in flight) — run shed, event recorded",
					env.Source, env.ID, cap(s.runSem))
			}
		}
	}
	_ = s.ingressChain.Append(ingress.RecordOf(env, disposition))

	writeJSON(w, status, map[string]any{
		"id": env.ID, "source": env.Source, "type": env.Type,
		"attributed": env.Attributed, "disposition": disposition,
		"recipe": routedRecipe(matched, def, disposition),
	})
}

// claimRecipe takes the single-flight claim for a recipe. false => a run for it is already in
// flight and this event is duplicate work. A nil map (no ingress model configured) always claims.
func (s *Server) claimRecipe(recipe string) bool {
	if s.inFlight == nil {
		return true
	}
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	if s.inFlight[recipe] {
		return false
	}
	s.inFlight[recipe] = true
	return true
}

// releaseRecipe drops the claim. Deferred inside the run goroutine, so a panicking run cannot
// leave a recipe permanently claimed — that would silently stop it running ever again.
func (s *Server) releaseRecipe(recipe string) {
	if s.inFlight == nil {
		return
	}
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	delete(s.inFlight, recipe)
}

// acquireRun reserves one in-flight governed-run slot. It never blocks: false means the cap is
// full and the caller must shed. A nil semaphore means unbounded (no cap configured).
func (s *Server) acquireRun() bool {
	if s.runSem == nil {
		return true
	}
	select {
	case s.runSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseRun returns a slot. Safe on a nil semaphore so the unbounded path needs no special case.
func (s *Server) releaseRun() {
	if s.runSem == nil {
		return
	}
	select {
	case <-s.runSem:
	default: // never block on release; a spurious release is not worth deadlocking over
	}
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
	}, emitpkg.NewOrchestrationContext(env.ID))
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
