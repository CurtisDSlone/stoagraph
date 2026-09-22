package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
)

// The existing panic tests contain the panic INSIDE their fake run, so they prove the deferred
// releases work, not that the process survives. This one does not recover in the fake: an
// unrecovered panic in a goroutine kills the test binary, so the test passing at all IS the
// evidence that production contains it. The slot and claim must still come back.
func TestPanickingRunDoesNotKillTheProcess(t *testing.T) {
	done := make(chan struct{}, 4)
	var calls atomic.Int32
	s, _, secret := capServer(t, 1, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		defer func() { done <- struct{}{} }() // runs during unwinding, before the recover upstream
		if calls.Add(1) == 1 {
			panic("run exploded with nobody catching it")
		}
	})

	if d := post(t, s, secret, "boom"); !strings.HasPrefix(d, "dispatched:") {
		t.Fatalf("first event: %q", d)
	}
	<-done
	time.Sleep(50 * time.Millisecond) // let the deferred releases land

	// Still here: the process survived. Now: did the panicking run give its slot back?
	if d := post(t, s, secret, "after"); !strings.HasPrefix(d, "dispatched:") {
		t.Errorf("after an unrecovered-in-run panic the slot leaked: %q", d)
	}
	<-done
}
