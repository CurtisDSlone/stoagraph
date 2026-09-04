// Package dispatch executes a recipe's AUTHORIZED calls. The kernel authorizes; this
// package is transport — and the separation is the point.
//
// stag.Eval performs no I/O: an `invoke` step resolves its arguments from slots, clears
// them against its rule, and emits a stag.AuthorizedCall. Execute takes that sequence and
// makes the calls, RE-CROSSING every one through the gate against that tool's own route
// and its own recipe. So a recipe's authorization to propose a call is never authority to
// make it: the target's own policy still fires, and a recipe cannot launder an action by
// naming it in an invoke.
//
// The sequence HALTS on the first refusal and does not roll back. Steps that already ran
// stay run, and the result says exactly where it stopped — the gate does not claim a
// transactional guarantee it cannot provide over arbitrary third-party tools.
package dispatch

// file-kw: dispatch executor authorized calls re-cross gate transport halt no-rollback sequence invoke

import (
	"context"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// Decider is the gate seam: proxy.Gate satisfies it. Taking the interface (not the
// concrete Gate) keeps this package testable without a live route table, and keeps the
// dependency pointing at the gate rather than around it.
// kw: decider seam gate decide re-cross
type Decider interface {
	Decide(ctx context.Context, call proxy.ToolCall) proxy.Decision
}

// Transport carries a cleared call to the downstream tool. It is consulted ONLY for a
// call the gate forwarded.
// kw: transport downstream carry cleared call
type Transport interface {
	Call(ctx context.Context, call proxy.ToolCall) (string, error)
}

// StepResult is what happened to one authorized call.
// kw: step result verdict made error approval per-call outcome
type StepResult struct {
	StepID     string       `json:"step_id"`
	Tool       string       `json:"tool"`
	Verdict    stag.Verdict `json:"verdict"`
	Made       bool         `json:"made"`  // the call actually reached the tool AND returned
	Value      string       `json:"value"` // the downstream's response, when it was made
	ApprovalID string       `json:"approval_id,omitempty"`
	// Attempts is how many polls an await actually took (1 for an ordinary call). The audit must
	// not claim one call where six happened.
	Attempts int `json:"attempts,omitempty"`
	// Unmet is set when an await exhausted its attempts without its condition holding. It is
	// distinct from Error: the tool answered every time, the world just never reached the state
	// the policy was waiting for.
	Unmet bool `json:"unmet,omitempty"`
	// Error is a TRANSPORT failure, never a policy refusal. A denied call has Made=false
	// and an empty Error; a call the gate allowed but the downstream refused has
	// Verdict=Allow and an Error. Conflating them would misreport the audit.
	Error string `json:"error,omitempty"`
}

// Result is the outcome of the whole sequence.
// kw: sequence result complete halted-at steps
type Result struct {
	Steps    []StepResult `json:"steps"`
	Complete bool         `json:"complete"`            // every authorized call was made
	HaltedAt string       `json:"halted_at,omitempty"` // the step id the sequence stopped on
}

// sleepCtx waits d milliseconds, returning false if the context is cancelled first — so a
// cancelled sequence stops promptly instead of sleeping out its remaining attempts.
// kw: sleep context cancellable poll interval
func sleepCtx(ctx context.Context, ms int) bool {
	if ms <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Execute makes each authorized call in order, re-crossing every one through the gate.
// It stops at the first call the gate does not forward or the transport does not carry.
// kw: execute sequence order halt first-refusal re-cross verbatim
func Execute(ctx context.Context, g Decider, t Transport, calls []stag.AuthorizedCall) Result {
	var res Result
	res.Complete = true
	for _, c := range calls {
		if err := ctx.Err(); err != nil {
			res.Complete, res.HaltedAt = false, c.StepID
			return res
		}
		// fail closed: a call with no tool is refused before it reaches anything
		if c.Tool == "" {
			res.Steps = append(res.Steps, StepResult{StepID: c.StepID, Verdict: stag.Deny})
			res.Complete, res.HaltedAt = false, c.StepID
			return res
		}
		// the authorized arguments are forwarded VERBATIM: the executor may not add,
		// drop or edit an argument the kernel cleared.
		args := make(map[string]string, len(c.Args))
		for k, v := range c.Args {
			args[k] = v
		}
		call := proxy.ToolCall{Tool: c.Tool, Args: args}

		// THE re-crossing: this tool's own route, this tool's own recipe.
		dec := g.Decide(ctx, call)
		step := StepResult{StepID: c.StepID, Tool: c.Tool, Verdict: dec.Verdict, ApprovalID: dec.ApprovalID}
		if !dec.Forward {
			res.Steps = append(res.Steps, step)
			res.Complete, res.HaltedAt = false, c.StepID
			return res
		}
		if t == nil {
			step.Error = "no transport"
			res.Steps = append(res.Steps, step)
			res.Complete, res.HaltedAt = false, c.StepID
			return res
		}
		val, err := t.Call(ctx, call)
		if err != nil {
			step.Attempts = 1
			step.Error = err.Error() // transport failure, NOT a policy refusal
			res.Steps = append(res.Steps, step)
			res.Complete, res.HaltedAt = false, c.StepID
			return res
		}
		step.Attempts, step.Made, step.Value = 1, true, val

		// AWAIT: "do not proceed until this holds." The first call has already happened; if its
		// output does not satisfy the condition, wait and try again, up to the attempts the
		// kernel authorized.
		//
		// The output is read ONLY to decide continue-or-halt. It never becomes an argument to a
		// later call and never reaches a sink: a downstream's response is external untrusted
		// content, and letting it steer a subsequent action would be a new injection path into
		// the gate itself.
		if c.Until != nil {
			ok := c.Until.Release(val)
			for !ok && step.Attempts < c.Attempts {
				if !sleepCtx(ctx, c.DelayMS) {
					step.Made = false
					res.Steps = append(res.Steps, step)
					res.Complete, res.HaltedAt = false, c.StepID
					return res
				}
				// EVERY attempt re-crosses the gate: a poll is not a licence to call a tool
				// repeatedly unjudged, and a revocation mid-poll must stop it.
				if d := g.Decide(ctx, call); !d.Forward {
					step.Made, step.Verdict = false, d.Verdict
					res.Steps = append(res.Steps, step)
					res.Complete, res.HaltedAt = false, c.StepID
					return res
				}
				step.Attempts++
				v, cerr := t.Call(ctx, call)
				if cerr != nil {
					step.Made, step.Error = false, cerr.Error()
					res.Steps = append(res.Steps, step)
					res.Complete, res.HaltedAt = false, c.StepID
					return res
				}
				val, ok = v, c.Until.Release(v)
			}
			step.Value = val
			if !ok {
				// Exhausted. The tool answered every time; the world never reached the state the
				// policy required, so the steps that depend on it must not run.
				step.Made, step.Unmet = false, true
				res.Steps = append(res.Steps, step)
				res.Complete, res.HaltedAt = false, c.StepID
				return res
			}
		}
		res.Steps = append(res.Steps, step)
	}
	return res
}
