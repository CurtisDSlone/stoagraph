// Package stag is the public entry point to the StAG kernel: Eval, the recipe
// evaluator that composes the internal trust/gate/release/record primitives into
// the product's load-bearing guarantee (no non-authoritative value reaches an
// authoritative sink at Allow without both a gate verdict and a recorded
// ReleaseEvent), plus re-exports of the primitive types and constants a caller
// needs to build a Recipe. The primitives themselves are internal and fixed.
package stag

// file-kw: stag public api recipe eval compose kernel invariant facade re-export graph walk branch gate

import (
	"encoding/json"
	"fmt"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/gate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/record"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/release"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

// Re-exported primitive types (the internal packages stay private).
type (
	TrustClass      = trust.TrustClass
	Verdict         = gate.Verdict
	SinkSensitivity = gate.SinkSensitivity
	RuleKind        = release.RuleKind
	ReleaseRule     = release.ReleaseRule
	ReleaseEvent    = record.ReleaseEvent
	// DecisionRecord is the audit chain's unit: one leaf per DECISION (allow, deny or escalate),
	// carrying its releases only when the call was actually forwarded.
	DecisionRecord = record.DecisionRecord
)

// Re-exported constants, so a caller can build recipes without the internals.
const (
	Untrusted     = trust.Untrusted
	Caller        = trust.Caller
	Authoritative = trust.Authoritative

	Allow    = gate.Allow
	Escalate = gate.Escalate
	Deny     = gate.Deny

	SinkBenign        = gate.SinkBenign
	SinkAuthoritative = gate.SinkAuthoritative

	RuleSetMembership  = release.RuleSetMembership
	RuleSignedEquality = release.RuleSignedEquality
	RuleNumericRange   = release.RuleNumericRange
)

// kw: facade re-exports one hashing discipline one enum register
func CanonicalHash(v any) (string, error) { return record.CanonicalHash(v) }

// kw: parse inverses re-export fail-closed
func ParseTrustClass(s string) (TrustClass, error)           { return trust.ParseTrustClass(s) }
func ParseSinkSensitivity(s string) (SinkSensitivity, error) { return gate.ParseSinkSensitivity(s) }
func ParseRuleKind(s string) (RuleKind, error)               { return release.ParseRuleKind(s) }

// kw: bind graph slot value class origin
type Slot struct {
	Value  string
	Class  TrustClass
	Origin string
}

// kw: recipe node kind propose sink branch gate
type NodeKind int

// kw: node kind constants propose sink branch gate
const (
	NodePropose NodeKind = iota
	NodeSink
	NodeBranch
	NodeGate
	NodeForeach
	NodeExit
)

// foreachCap is the fixed max number of elements a foreach may iterate — an
// author-unraisable kernel bound (inv 13); a longer list fails closed.
const foreachCap = 64

// kw: node kind string canonical register
func (k NodeKind) String() string {
	switch k {
	case NodePropose:
		return "propose"
	case NodeSink:
		return "sink"
	case NodeBranch:
		return "branch"
	case NodeGate:
		return "gate"
	case NodeForeach:
		return "foreach"
	case NodeExit:
		return "exit"
	default:
		return "unknown"
	}
}

// kw: parse node kind fail-closed inverse of string
func ParseNodeKind(s string) (NodeKind, error) {
	switch s {
	case "propose":
		return NodePropose, nil
	case "sink":
		return NodeSink, nil
	case "branch":
		return NodeBranch, nil
	case "gate":
		return NodeGate, nil
	case "foreach":
		return NodeForeach, nil
	case "exit":
		return NodeExit, nil
	default:
		return NodeKind(-1), fmt.Errorf("invalid node kind: %q", s) // fail closed (inv 8)
	}
}

// kw: branch case closed predicate forward edge
type Case struct {
	Rule *ReleaseRule
	Goto string
}

// kw: recipe step propose sink branch gate forward-only edges
type Step struct {
	Id          string
	Kind        NodeKind
	Out         string
	In          string
	As          string // foreach: the per-element out-slot bound each iteration
	Sensitivity SinkSensitivity
	Rule        *ReleaseRule
	RuleID      string
	Field       string
	Actor       string
	Goto        string // optional forward edge; "" = fall-through
	Escalate    bool   // gate on-fail: false=Deny (default), true=Escalate
	Cases       []Case // branch
	Default     string // branch
}

// kw: recipe ingredients steps
type Recipe struct {
	Ingredients map[string]Slot
	Steps       []Step
	// PassThrough names the tool arguments this policy KNOWINGLY forwards ungated. It is the
	// coverage contract: an argument is either gated (a propose slot fed by a GateArg path) or
	// listed here. An argument that is neither is unaccounted for, and the gate denies the call.
	//
	// It lives in the recipe (not the route) because it is a security decision and must ride in
	// the SemanticHash: widening coverage has to change the policy identity the audit records.
	// A route-side declaration would leave the signed record unable to tell a gated argument from
	// one silently waved through.
	PassThrough []string
}

// kw: sink outcome verdict per sink
type SinkOutcome struct {
	Field    string
	Subject  TrustClass
	Sink     SinkSensitivity
	Released bool
	Verdict  Verdict
}

// kw: gate outcome checkpoint pass fail escalate
type GateOutcome struct {
	Id      string
	Subject TrustClass
	Passed  bool
	Verdict Verdict
}

// kw: eval result verdict sinks gates events fault
type EvalResult struct {
	Verdict Verdict
	Sinks   []SinkOutcome
	Gates   []GateOutcome
	Events  []ReleaseEvent
	Fault   string // "" = none; else fail-closed structural halt (inv 8/10)
}

// kw: eval recipe path walk forward-only compose kernel invariant foreach single-arg
func Eval(r Recipe, proposal string, recipeHash string) EvalResult {
	// single input: every `propose` binds the one proposal (backward-compatible).
	return evalWith(r, func(string) string { return proposal }, recipeHash)
}

// EvalArgs gates over SEVERAL named inputs: each `propose out: X` binds the untrusted value
// args[X]. This lets one recipe decide from multiple arguments of a tool call (e.g. namespace
// AND replicas), not just one. An absent key binds "" (which fails a rule — fail closed).
// kw: eval multi-arg named inputs propose-by-name
func EvalArgs(r Recipe, args map[string]string, recipeHash string) EvalResult {
	return evalWith(r, func(out string) string { return args[out] }, recipeHash)
}

// evalWith is the shared core: bind(out) supplies the untrusted value for each propose's
// out-slot (constant proposal for Eval; per-name for EvalArgs).
func evalWith(r Recipe, bind func(string) string, recipeHash string) EvalResult {
	slots := make(map[string]Slot, len(r.Ingredients))
	for k, v := range r.Ingredients {
		slots[k] = v
	}
	idx := make(map[string]int, len(r.Steps)) // ids by first occurrence
	for i, s := range r.Steps {
		if _, seen := idx[s.Id]; !seen {
			idx[s.Id] = i
		}
	}
	res, verdicts := walk(r, idx, slots, bind, recipeHash, 0, 0, 0)
	res.Verdict = gate.AndAll(verdicts...)
	return res
}

// walk walks the recipe graph from step `start` to a terminal, returning the
// accumulated outcomes and per-step verdicts (the caller folds them with AndAll).
// depth>0 means we are inside a foreach body (nesting is refused); elem is the
// foreach iteration ordinal, folded into ReleaseEvent.Ordering so each element's
// crossing is distinct. At the top level elem is 0, so a non-foreach recipe is
// byte-identical to before the refactor (Ordering == the step index).
func walk(r Recipe, idx map[string]int, slots map[string]Slot, bind func(string) string, recipeHash string, start, depth int, elem int64) (EvalResult, []Verdict) {
	var res EvalResult
	var verdicts []Verdict
	stepCount := int64(len(r.Steps))
	// hop: "" = fall-through; else a known, strictly-forward id
	hop := func(i int, target string) (int, bool) {
		if target == "" {
			return i + 1, true
		}
		j, ok := idx[target]
		if !ok || j <= i {
			return 0, false
		}
		return j, true
	}
	fault := func(reason string) {
		res.Fault = reason
		verdicts = append(verdicts, Deny) // fail closed (inv 8/10)
	}
	i := start
walk:
	for i < len(r.Steps) {
		step := r.Steps[i]
		switch step.Kind {
		case NodePropose:
			// the agent's output is untrusted-until-gated; bind(out) is the value for
			// this out-slot (the single proposal, or the named arg for a multi-arg call).
			slots[step.Out] = Slot{Value: bind(step.Out), Class: Untrusted, Origin: "propose"}
			n, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			i = n
		case NodeSink:
			// the crossing gate: refuses the crossing, never the movement
			s, ok := slots[step.In]
			if !ok {
				s = Slot{Class: TrustClass(-1)} // missing slot: severed label, fails closed
			}
			released := ok && step.Rule != nil && step.Rule.Release(s.Value) // a missing slot never releases
			v := gate.GateSink(s.Class, step.Sensitivity, released)
			res.Sinks = append(res.Sinks, SinkOutcome{Field: step.Field, Subject: s.Class, Sink: step.Sensitivity, Released: released, Verdict: v})
			verdicts = append(verdicts, v)
			// structural: the same step that clears the crossing records it (inv 2)
			if step.Sensitivity == SinkAuthoritative && s.Class != Authoritative && released {
				res.Events = append(res.Events, ReleaseEvent{
					SubjectClass: s.Class, SubjectOrigin: s.Origin, CollectedField: step.In,
					TargetClass: Authoritative, TargetField: step.Field,
					AuthorizingRule: step.RuleID, Actor: step.Actor,
					Ordering:   elem*stepCount + int64(i), // per-element ordinal (elem 0 => step index)
					RecipeHash: recipeHash,
				})
			}
			n, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			i = n
		case NodeGate:
			// the checkpoint: guards the movement; halts the path on failure
			s, present := slots[step.In]
			subj := s.Class
			if !present {
				subj = TrustClass(-1) // severed
			}
			if present && step.Rule != nil && step.Rule.Release(s.Value) {
				res.Gates = append(res.Gates, GateOutcome{Id: step.Id, Subject: subj, Passed: true, Verdict: Allow})
				verdicts = append(verdicts, Allow)
				n, ok := hop(i, step.Goto)
				if !ok {
					fault("edge " + step.Id)
					break walk
				}
				i = n
				continue
			}
			v := Deny // severed slot or absent rule always Deny (inv 8)
			if present && step.Rule != nil && step.Escalate {
				v = Escalate // declared on-fail, genuine predicate failure only
			}
			res.Gates = append(res.Gates, GateOutcome{Id: step.Id, Subject: subj, Passed: false, Verdict: v})
			verdicts = append(verdicts, v)
			break walk // halt
		case NodeBranch:
			// routing, never enforcement; edges are always explicit
			s, present := slots[step.In]
			if !present {
				fault("branch " + step.Id) // routing on uncertainty refused
				break walk
			}
			target := step.Default
			for _, c := range step.Cases {
				if c.Rule != nil && c.Rule.Release(s.Value) {
					target = c.Goto
					break
				}
			}
			j, ok := idx[target]
			if target == "" || !ok || j <= i {
				fault("branch " + step.Id)
				break walk
			}
			i = j
		case NodeForeach:
			// bounded fan-out: gate EACH element of a runtime list (inv 13 cap).
			if depth > 0 {
				fault("nested foreach " + step.Id) // no nesting in v1
				break walk
			}
			s, ok := slots[step.In]
			if !ok {
				fault("foreach severed slot " + step.Id) // fail closed
				break walk
			}
			var elems []string
			if err := json.Unmarshal([]byte(s.Value), &elems); err != nil {
				fault("foreach: not a JSON string array " + step.Id)
				break walk
			}
			if len(elems) > foreachCap {
				fault("foreach: over cap " + step.Id) // author-unraisable bound
				break walk
			}
			body, ok := hop(i, step.Goto)
			if !ok {
				fault("edge " + step.Id)
				break walk
			}
			for k, e := range elems {
				// each element enters the body fresh and untrusted (declassifying boundary)
				slots[step.As] = Slot{Value: e, Class: Untrusted, Origin: "foreach"}
				inner, innerV := walk(r, idx, slots, bind, recipeHash, body, depth+1, int64(k))
				res.Sinks = append(res.Sinks, inner.Sinks...)
				res.Gates = append(res.Gates, inner.Gates...)
				res.Events = append(res.Events, inner.Events...)
				verdicts = append(verdicts, innerV...) // AndAll'd by the caller: one deny denies the batch
				if inner.Fault != "" && res.Fault == "" {
					res.Fault = inner.Fault
				}
			}
			break walk // foreach is a tail construct: it consumed the rest of the path
		case NodeExit:
			break walk // explicit terminal: halt the path, add no verdict and no crossing
		default:
			fault("kind " + step.Id) // complete mediation (inv 10)
			break walk
		}
	}
	return res, verdicts
}
