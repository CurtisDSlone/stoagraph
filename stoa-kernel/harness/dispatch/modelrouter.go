package dispatch

// file-kw: dispatch model role router openai constrained-json propose recipe-id confidence enum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model/openai"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/store"
)

// routeSystem steers the dispatch model. The output is constrained JSON; the deterministic Gate is
// the real decision layer, so the prompt just asks for an honest constrained proposal.
const routeSystem = "You are an event router. Map an inbound event to exactly ONE recipe from a " +
	"fixed list, or 'none' if none fits. You never invent a recipe id. Rate confidence honestly. " +
	"Respond with ONLY a JSON object: {\"recipe_id\": <id or \"none\">, \"confidence\": \"high\"|\"medium\"|\"low\"}."

// modelRouter is the dispatch model role: a configured model (selected by name, same config as any
// other model) that proposes a recipe id. Ratchet's Models.Dispatch, in the harness.
type modelRouter struct {
	client openai.Client
	name   string
}

// NewRouter builds a dispatch Router from a configured model. The dispatcher is just another model
// the operator picked — no special config. (Claude-kind support is a follow-up; the operator uses
// an openai-kind model as the dispatcher for now.)
func NewRouter(m store.Model) (Router, error) {
	switch m.Kind {
	case "openai":
		return modelRouter{
			client: openai.Client{
				BaseURL:   m.BaseURL,
				APIKey:    m.Key(),
				Model:     m.Model,
				MaxTokens: 256, // one constrained JSON object; keep it small
				// the same per-model budget: routing an event is a model call like any other,
				// and a gated endpoint is no faster for being asked a short question.
				HTTP: &http.Client{Timeout: m.RequestTimeout()},
			},
			name: m.Name,
		}, nil
	case "claude":
		return nil, fmt.Errorf("dispatch model %q: claude-kind not yet supported — select an openai-kind model", m.Name)
	default:
		return nil, fmt.Errorf("dispatch model %q: unknown kind %q", m.Name, m.Kind)
	}
}

func (r modelRouter) Name() string { return "dispatch:" + r.name }

// Route asks the dispatch model for a recipe id + confidence over the candidate list. The reply is
// parsed leniently (first JSON object); a garbled reply degrades to {none, low}, which the Gate
// rejects — fail closed.
func (r modelRouter) Route(ctx context.Context, event Event, candidates []Recipe) (RouteResult, error) {
	prop, err := r.client.Propose(ctx, model.Request{System: routeSystem, Input: routePrompt(event, candidates)})
	if err != nil {
		return RouteResult{}, err
	}
	return parseRoute(prop.Value), nil
}

func routePrompt(event Event, candidates []Recipe) string {
	var b strings.Builder
	b.WriteString("Recipes (choose one id, or \"none\"):\n")
	for _, c := range candidates {
		b.WriteString("- ")
		b.WriteString(c.ID)
		if c.WhenToUse != "" {
			b.WriteString(": ")
			b.WriteString(c.WhenToUse)
		}
		b.WriteByte('\n')
	}
	payload, _ := json.Marshal(map[string]any(event))
	b.WriteString("\nEvent:\n")
	b.Write(payload)
	b.WriteString("\n\nReturn JSON {recipe_id, confidence}.")
	return b.String()
}

// parseRoute extracts {recipe_id, confidence} from the model reply, tolerating surrounding prose or
// code fences. Defaults are the fail-closed values (none/low).
func parseRoute(content string) RouteResult {
	rr := RouteResult{RecipeID: "none", Confidence: "low"}
	obj := firstJSONObject(content)
	if obj == "" {
		return rr
	}
	var v struct {
		RecipeID   string `json:"recipe_id"`
		Confidence string `json:"confidence"`
	}
	if json.Unmarshal([]byte(obj), &v) == nil {
		if v.RecipeID != "" {
			rr.RecipeID = v.RecipeID
		}
		if v.Confidence != "" {
			rr.Confidence = strings.ToLower(strings.TrimSpace(v.Confidence))
		}
	}
	return rr
}

// firstJSONObject returns the first brace-balanced {...} in s (handles fences/prose around the JSON).
func firstJSONObject(s string) string {
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return ""
	}
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[i : j+1]
			}
		}
	}
	return ""
}
