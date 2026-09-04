// Package router resolves the persisted route table (Planning/18) into a live
// proxy.Router — the step that makes the gate MULTI-TOOL from saved bindings. A
// stored route binds a tool to a recipe BY NAME + a gated arg; Build loads and
// parses each recipe into the kernel form. Fail closed: a route whose recipe is
// missing or invalid produces NO router entry (and an error) — the tool is left
// unrouted, which the gate denies (U22). The router never holds a broken recipe.
package router

// file-kw: route resolve build proxy router recipe-by-name fail-closed multi-tool gate binding

import (
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
)

// kw: spec tool recipe-name gate-arg (a stored binding)
type Spec struct {
	Tool    string
	Server  string // the MCP server this tool is dispatched to. Declared, never inferred.
	Recipe  string
	GateArg string
	// Sequenced: this binding exists only so a recipe's `invoke` may authorize calls to it.
	// Not advertised, and unreachable without a live grant. Zero value = an ordinary route.
	Sequenced bool
}

// RouteError names the binding that failed to resolve. It carries the SERVER as well as the tool:
// a bare tool name no longer identifies one route, so an error reported against `search_code` alone
// could not say which of two servers' bindings was broken.
// kw: route error tool server recipe reason unresolved
type RouteError struct {
	Tool   string
	Server string
	Recipe string
	Err    string
}

// kw: resolved router errors warnings
type Resolved struct {
	Router proxy.Router
	Errors []RouteError
	// Warnings are non-fatal bind-time notes about routes that DID bind — today, recipes whose leakage
	// is unbounded (a declared free-text passthrough reaches an external sink) served in the default
	// (non-strict) mode. They void the per-session leakage bound for that route, so the operator should
	// see them; in strict mode (BuildStrict requireBounded) the same condition becomes an Error and the
	// route is dropped. Callers log these; the console can surface them.
	Warnings []RouteError
}

// Build resolves specs in the DEFAULT (non-strict) mode: an unbounded-leakage recipe still binds, but is
// reported in Warnings. Passthrough (free-text) fields are a legitimate, declared author choice
// (notify's message, ticket's summary), so refusing them by default would break real policies.
// kw: build resolve specs load parse fail-closed non-strict
func Build(specs []Spec, loadRecipe func(name string) ([]byte, error)) Resolved {
	return BuildStrict(specs, loadRecipe, false)
}

// BuildStrict resolves specs, optionally enforcing the leakage bound. When requireBounded is true, a
// recipe whose leakage is UNBOUNDED (recipe.Leakage) is REFUSED — no router entry, an Error with the
// reason, tool left unrouted, gate denies (Planning/34 §6.1). This is the high-assurance posture: the
// whole deployment keeps a computable per-session leakage ceiling. When false, such a route binds but is
// recorded in Warnings. A missing/invalid recipe is always a hard Error, strict or not.
// kw: build strict require-bounded leakage refuse advertise-time gate
func BuildStrict(specs []Spec, loadRecipe func(name string) ([]byte, error), requireBounded bool) Resolved {
	res := Resolved{Router: proxy.Router{}}
	for _, sp := range specs {
		src, err := loadRecipe(sp.Recipe)
		if err != nil {
			res.Errors = append(res.Errors, RouteError{Tool: sp.Tool, Server: sp.Server, Recipe: sp.Recipe, Err: err.Error()})
			continue
		}
		// Compose: a routed recipe may inline sub-recipes (goto_recipe); resolve them via
		// the same loader. A plain recipe composes to itself. The gate binds the COMPOSED
		// hash, so the audit proves exactly the policy that ran.
		p, _, err := recipe.Compose(src, loadRecipe)
		if err != nil {
			res.Errors = append(res.Errors, RouteError{Tool: sp.Tool, Server: sp.Server, Recipe: sp.Recipe, Err: err.Error()})
			continue // fail closed: no entry -> tool unrouted -> gate denies
		}
		// LEAKAGE, bind-time (Planning/34). A route has no computable per-session leakage ceiling if EITHER
		// the recipe itself is unbounded (a declared passthrough / ungated sink reaches an external sink),
		// OR the route forwards a gate-arg argument the recipe never constrains with a bounding rule
		// (boundedness is a property of the (recipe, gateArg) pair — the gate forwards the whole raw call,
		// so a "covered" but unconstrained argument crosses as free-text). In strict mode that voids the
		// deployment's guarantee, so refuse the route (fail closed, like an invalid recipe); otherwise bind
		// it but flag it, so the operator sees what they are accepting.
		var unboundedReason string
		if lk := recipe.Leakage(p.Recipe); lk.Unbounded {
			unboundedReason = lk.UnboundedReason
		} else if ft := recipe.RouteFreeText(p.Recipe, sp.GateArg); len(ft) > 0 {
			unboundedReason = "gated argument(s) forward free-text (no constraining rule): " + strings.Join(ft, ", ")
		}
		if unboundedReason != "" {
			re := RouteError{Tool: sp.Tool, Server: sp.Server, Recipe: sp.Recipe, Err: "unbounded leakage: " + unboundedReason}
			if requireBounded {
				res.Errors = append(res.Errors, re)
				continue // fail closed: no entry -> tool unrouted -> gate denies
			}
			res.Warnings = append(res.Warnings, re)
		}
		// Keyed by the ADVERTISED name (<server>__<tool>) — the name the agent will call. Two servers
		// exposing the same tool therefore produce two distinct entries instead of one overwriting the
		// other. Route.Tool keeps the downstream's own name, which is what a cleared call is forwarded as.
		res.Router[proxy.AdvertisedName(sp.Server, sp.Tool)] = proxy.Route{
			Recipe:     p.Recipe,
			RecipeHash: p.SemanticHash,
			GateArg:    sp.GateArg,
			Sequenced:  sp.Sequenced,
			RecipeName: sp.Recipe,
			Server:     sp.Server,
			Tool:       sp.Tool,
		}
	}
	return res
}
