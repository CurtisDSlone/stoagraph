// Package model is the proposer boundary: the untrusted agent side. A strategy
// seam that produces the proposal the kernel gates, conferring zero trust - a
// Proposal has nowhere to put trust, and Decide's verdict depends only on the
// proposal value, never on which model produced it.
package model

// file-kw: proposer strategy adapter untrusted proposal decide zero-trust provenance fail-closed

import (
	"context"
	"fmt"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// kw: request bound context proposer reasons over as data
type Request struct {
	Recipe string
	System string
	Input  string
}

// kw: proposal trust-free value provenance never authorizes
type Proposal struct {
	Value string
	Model string
}

// kw: proposer strategy bring your agent
type Proposer interface {
	Propose(ctx context.Context, req Request) (Proposal, error)
}

// kw: localstub deterministic offline proposer
type LocalStub struct {
	Name      string
	Responses map[string]string
	Default   string
	Err       error
}

// kw: localstub propose deterministic fail path
func (s LocalStub) Propose(ctx context.Context, req Request) (Proposal, error) {
	if s.Err != nil {
		return Proposal{}, s.Err
	}
	v, ok := s.Responses[req.Input]
	if !ok {
		v = s.Default
	}
	return Proposal{Value: v, Model: "localstub:" + s.Name}, nil
}

// kw: decision proposal result
type Decision struct {
	Proposal Proposal
	Result   stag.EvalResult
}

// kw: decide compose proposer gate pure pass-through fail-closed
func Decide(ctx context.Context, r stag.Recipe, recipeHash string, p Proposer, req Request) (Decision, error) {
	prop, err := p.Propose(ctx, req)
	if err != nil {
		// fail closed (inv 8): no proposal to gate -> Deny, carried in the result
		return Decision{Result: stag.EvalResult{Verdict: stag.Deny, Fault: fmt.Sprintf("proposer: %v", err)}}, err
	}
	// pure composition: Eval stamps prop.Value Untrusted; Decide adds no trust
	return Decision{Proposal: prop, Result: stag.Eval(r, prop.Value, recipeHash)}, nil
}
