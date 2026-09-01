// Package stoakernel_test holds the architectural invariants of the merged module (Planning/26).
//
// Merging the gate and the orchestrator into one Go module bought a simpler build — but it removed
// the module boundary that USED to make the central claim structurally true. These tests put that
// boundary back as an enforced rule, so the claim cannot quietly rot into a convention.
package stoakernel_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestGateDependsOnNothingInTheOrchestrator is the load-bearing architectural test.
//
// The product's central claim is that the GATE holds no model and no keys — that is why it can be
// trusted to enforce policy on an untrusted agent, and why it ships as its own container. That claim
// is only credible if the gate cannot even REACH the orchestrator's code (models, API keys, the agent
// loop). The dependency runs ONE WAY: harness -> stag, never the reverse.
//
// If this test fails, someone has imported orchestrator code into the gate. That is not a style
// problem; it is the product-defining invariant breaking, and no amount of "but it works" makes it
// safe to ship.
func TestGateDependsOnNothingInTheOrchestrator(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./stag/...").Output()
	if err != nil {
		t.Fatalf("go list -deps ./stag/...: %v", err)
	}
	const orchestrator = "github.com/CurtisDSlone/stoagraph/stoa-kernel/harness"
	var bad []string
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(pkg, orchestrator) {
			bad = append(bad, pkg)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("ARCHITECTURE BREACH: the gate (stag/) imports orchestrator code — the gate is supposed to hold\n"+
			"no model and no keys, and this makes that claim false:\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestGateBinariesDependOnNothingInTheOrchestrator extends the rule to the shipped ARTIFACTS: the
// stag-serve and stag-proxy containers must not link any orchestrator code either. A clean stag/
// package tree would still be undermined if the gate's own main() reached into harness/.
func TestGateBinariesDependOnNothingInTheOrchestrator(t *testing.T) {
	for _, bin := range []string{"./cmd/stag-serve", "./cmd/stag-proxy"} {
		out, err := exec.Command("go", "list", "-deps", bin).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", bin, err)
		}
		const orchestrator = "github.com/CurtisDSlone/stoagraph/stoa-kernel/harness"
		for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasPrefix(pkg, orchestrator) {
				t.Errorf("ARCHITECTURE BREACH: gate binary %s links orchestrator package %s", bin, pkg)
			}
		}
	}
}
