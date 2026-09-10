// Package dispatch routes an EVENT to a RECIPE, then (slice 2) binds a session and runs the agent
// loop against it. It is the orchestration analog of stag's own gate — and a port of Ratchet's
// dispatcher (internal/dispatch): the model proposes into a constrained slot (a recipe id from an
// enum) and a deterministic Gate decides. Resolution is deterministic-first: a user-authored event
// map matches structured events with no model at all; only unmatched/ambiguous events fall through
// to the dispatch model.
//
// Load-bearing property (Planning/25): a MISROUTE CANNOT BREACH. If the dispatcher picks the wrong
// recipe, stag still enforces THAT recipe faithfully — a bad route wastes a turn, it never lets
// anything cross. That is why a model is allowed in the routing path: the gate is the backstop.
package dispatch

// file-kw: dispatch event recipe route propose gate deterministic-first model-fallback misroute-cant-breach

import (
	"context"
	"strings"
)

// Recipe is a routable recipe (catalog entry): its id and a one-line "when to use" the router reads.
type Recipe struct {
	ID        string `json:"id"`
	WhenToUse string `json:"whenToUse"`
}

// RouteResult is the dispatch model's constrained proposal: one recipe id (or "none") + confidence.
type RouteResult struct {
	RecipeID   string
	Confidence string // high | medium | low
}

// Router is the dispatch model role: propose ONE recipe for an event from the candidate list, with
// honest confidence. Implemented by a configured model (modelRouter) or a stub (tests).
type Router interface {
	Route(ctx context.Context, event Event, candidates []Recipe) (RouteResult, error)
	Name() string
}

// GateDecision is the deterministic router gate's verdict (port of Ratchet's Gate).
type GateDecision int

const (
	// GateMatch: the proposal names an on-list recipe at non-low confidence.
	GateMatch GateDecision = iota
	// GateFallback: the proposal is rejected (no dispatch).
	GateFallback
)

// Gate is the deterministic gate on the router's proposal: proceed only if it names an on-list
// recipe at non-low confidence. Pure + exported so tests cover it without a model. This is the
// SAME shape as Ratchet's flow gate — the model can only ever name a real recipe, and low-confidence
// guesses are refused.
func Gate(recipeID, confidence string, validIDs []string) GateDecision {
	if recipeID == "" || recipeID == "none" {
		return GateFallback
	}
	if !Contains(validIDs, recipeID) {
		return GateFallback
	}
	if strings.ToLower(strings.TrimSpace(confidence)) == "low" {
		return GateFallback
	}
	return GateMatch
}

// Decision is the dispatcher's resolution of an event.
type Decision struct {
	RecipeID   string // the recipe to govern the dispatched session ("" when Mode == "none")
	Confidence string // "high" for a deterministic match; the model's rating otherwise
	Mode       string // "deterministic" | "model" | "none"
	Definition string // the event-map definition id that matched (deterministic mode)
	Router     string // which dispatch model decided (model mode)
}

// Dispatched reports whether a recipe was selected.
func (d Decision) Dispatched() bool { return d.Mode == "deterministic" || d.Mode == "model" }

// Dispatcher resolves an event to a recipe. Map is the user-authored deterministic layer; Router is
// the dispatch model (may be nil → deterministic-only); Catalog supplies the routable recipes for
// the model path (and is not needed for a deterministic match).
type Dispatcher struct {
	Map     EventMap
	Router  Router
	Catalog func() ([]Recipe, error)
}

// Dispatch resolves one event: try the deterministic event map first (no model), then the dispatch
// model + Gate. Returns Mode "none" when nothing routes (fail closed — the caller dispatches nothing).
func (d Dispatcher) Dispatch(ctx context.Context, event Event) (Decision, error) {
	// 1. deterministic: a user-authored definition matches the payload -> its recipe, no model.
	if def, ok := d.Map.Match(event); ok && def.Route != routeModel {
		return Decision{RecipeID: def.Recipe, Confidence: "high", Mode: "deterministic", Definition: def.ID}, nil
	}

	// 2. model route: narrow (future) -> propose recipe_id -> Gate. A misroute is contained by the gate.
	if d.Router == nil {
		return Decision{Mode: "none"}, nil
	}
	cands, err := catalog(d.Catalog)
	if err != nil {
		return Decision{}, err
	}
	rr, err := d.Router.Route(ctx, event, cands)
	if err != nil {
		return Decision{}, err
	}
	if Gate(rr.RecipeID, rr.Confidence, RecipeIDs(cands)) == GateFallback {
		return Decision{Mode: "none", Confidence: rr.Confidence, Router: d.Router.Name()}, nil
	}
	return Decision{RecipeID: rr.RecipeID, Confidence: rr.Confidence, Mode: "model", Router: d.Router.Name()}, nil
}

func catalog(f func() ([]Recipe, error)) ([]Recipe, error) {
	if f == nil {
		return nil, nil
	}
	return f()
}

// RecipeIDs returns the IDs of rs, in order.
func RecipeIDs(rs []Recipe) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}

// Contains reports whether target appears in ss.
func Contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
