package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

// The webhook front door launches each accepted event in its own goroutine. Without a cap, one
// burst of events is one burst of concurrent model sessions. These assert the cap actually binds —
// a semaphore nothing consults is arithmetic, not a control.

// capServer builds a front door whose runEvent blocks until released, so a test can hold slots.
func capServer(t *testing.T, capacity int, run func(dispatch.Decision, dispatch.Event, ingress.Envelope)) (*Server, *bytes.Buffer, []byte) {
	t.Helper()
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"drift","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate"}]`)

	var chainbuf bytes.Buffer
	secret := []byte("shared")
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](&chainbuf),
		ingressSecret: secret,
		runEvent:      run,
	}
	if capacity > 0 {
		s.runSem = make(chan struct{}, capacity)
	}
	return s, &chainbuf, secret
}

// post delivers one signed webhook and returns the front door's disposition.
func post(t *testing.T, s *Server, secret []byte, id string) string {
	t.Helper()
	payload := []byte(`{"id":"` + id + `","type":"posture.drifted","source":"prooflayer"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
	rec := httptest.NewRecorder()
	s.webhook(rec, req)

	var resp struct {
		Disposition string `json:"disposition"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
	}
	return resp.Disposition
}

func TestRunCapShedsWhenFull(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	s, chain, secret := capServer(t, 2, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		started <- struct{}{}
		<-release // hold the slot
	})

	// Fill the cap.
	for i := 0; i < 2; i++ {
		if d := post(t, s, secret, "fill"); !strings.HasPrefix(d, "dispatched:") {
			t.Fatalf("event %d should have dispatched, got %q", i, d)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("held runs did not start")
		}
	}

	// The next one must SHED, not queue.
	if d := post(t, s, secret, "overflow"); d != "dropped:at-capacity" {
		t.Errorf("disposition = %q, want dropped:at-capacity", d)
	}
	select {
	case <-started:
		t.Error("a run started past the cap")
	case <-time.After(100 * time.Millisecond):
	}

	// The shed event is still RECORDED — the operator can see the cap biting.
	if !strings.Contains(chain.String(), "dropped:at-capacity") {
		t.Error("shed event was not recorded in the ingress chain")
	}
	close(release)
}

func TestRunCapReleasesSlot(t *testing.T) {
	var inFlight sync.WaitGroup
	gate := make(chan struct{})
	var starts atomic.Int32
	s, _, secret := capServer(t, 1, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		starts.Add(1)
		<-gate
		inFlight.Done()
	})

	inFlight.Add(1)
	if d := post(t, s, secret, "first"); !strings.HasPrefix(d, "dispatched:") {
		t.Fatalf("first event: %q", d)
	}
	if d := post(t, s, secret, "second"); d != "dropped:at-capacity" {
		t.Fatalf("second event should shed while the cap is full: %q", d)
	}

	close(gate) // let the first finish, releasing its slot
	inFlight.Wait()

	// A slot is free again, so a later event runs.
	inFlight.Add(1)
	gate2 := make(chan struct{})
	close(gate2)
	deadline := time.After(2 * time.Second)
	for {
		if d := post(t, s, secret, "third"); strings.HasPrefix(d, "dispatched:") {
			break
		}
		select {
		case <-deadline:
			t.Fatal("slot was never released — the cap leaked")
		case <-time.After(10 * time.Millisecond):
		}
	}
	inFlight.Wait()
	if starts.Load() < 2 {
		t.Errorf("starts = %d, want >= 2", starts.Load())
	}
}

// A run that PANICS must still release its slot. Otherwise the cap leaks to zero over time and
// the front door silently stops running anything.
func TestRunCapSurvivesPanickingRun(t *testing.T) {
	done := make(chan struct{}, 4)
	var calls atomic.Int32
	s, _, secret := capServer(t, 1, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		defer func() { done <- struct{}{} }()
		defer func() { _ = recover() }() // contain it; the deferred release is what we assert
		if calls.Add(1) == 1 {
			panic("run exploded")
		}
	})

	if d := post(t, s, secret, "boom"); !strings.HasPrefix(d, "dispatched:") {
		t.Fatalf("first event: %q", d)
	}
	<-done
	time.Sleep(50 * time.Millisecond) // let the deferred release land

	if d := post(t, s, secret, "after"); !strings.HasPrefix(d, "dispatched:") {
		t.Errorf("after a panicking run the slot leaked: %q", d)
	}
	<-done
}

// Concurrent accepts must never put more than `cap` runs in flight at once.
func TestRunCapHoldsUnderConcurrentAccepts(t *testing.T) {
	const capacity = 3
	var live, peak atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup

	s, _, secret := capServer(t, capacity, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		live.Add(-1)
		wg.Done()
	})

	// Far more accepts than capacity, all at once.
	var dispatched atomic.Int32
	var postWG sync.WaitGroup
	for i := 0; i < 32; i++ {
		postWG.Add(1)
		go func(i int) {
			defer postWG.Done()
			payload := []byte(`{"id":"c","type":"posture.drifted","source":"prooflayer"}`)
			req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
			req.SetPathValue("source", "prooflayer")
			req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
			rec := httptest.NewRecorder()
			s.webhook(rec, req)
			var resp struct {
				Disposition string `json:"disposition"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if strings.HasPrefix(resp.Disposition, "dispatched:") {
				dispatched.Add(1)
				wg.Add(1)
			}
		}(i)
	}
	postWG.Wait()

	if got := dispatched.Load(); got > capacity {
		t.Errorf("%d runs dispatched with cap %d", got, capacity)
	}
	close(release)
	wg.Wait()

	if p := peak.Load(); p > capacity {
		t.Errorf("peak in-flight = %d, exceeds cap %d", p, capacity)
	}
	t.Logf("32 concurrent accepts, cap %d: %d dispatched, peak in flight %d",
		capacity, dispatched.Load(), peak.Load())
}

// A nil semaphore means unbounded — the zero-value Server (and every existing test that builds
// one by literal) keeps working unchanged.
func TestNilSemaphoreIsUnbounded(t *testing.T) {
	var starts atomic.Int32
	done := make(chan struct{}, 8)
	s, _, secret := capServer(t, 0, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		starts.Add(1)
		done <- struct{}{}
	})
	for i := 0; i < 5; i++ {
		if d := post(t, s, secret, "u"); !strings.HasPrefix(d, "dispatched:") {
			t.Fatalf("event %d shed with no cap configured: %q", i, d)
		}
	}
	for i := 0; i < 5; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("uncapped runs did not all start")
		}
	}
}

// The cap resolves fail-safe: garbage or out-of-range falls back to the DEFAULT, never to
// unbounded. Same discipline as provider.Bounds() and emit.maxPayloadBytes().
func TestMaxConcurrentRunsEnvFailsSafe(t *testing.T) {
	for _, v := range []string{"", "0", "-1", "abc", "99999", "1e3"} {
		t.Run("v="+v, func(t *testing.T) {
			t.Setenv("STOA_MAX_CONCURRENT_RUNS", v)
			if got := maxConcurrentRuns(); got != defaultMaxConcurrentRuns {
				t.Errorf("STOA_MAX_CONCURRENT_RUNS=%q gave %d, want default %d", v, got, defaultMaxConcurrentRuns)
			}
		})
	}
}

func TestMaxConcurrentRunsEnvOverrides(t *testing.T) {
	t.Setenv("STOA_MAX_CONCURRENT_RUNS", "12")
	if got := maxConcurrentRuns(); got != 12 {
		t.Errorf("maxConcurrentRuns() = %d, want 12", got)
	}
	t.Setenv("STOA_MAX_CONCURRENT_RUNS", "64") // the ceiling itself is allowed
	if got := maxConcurrentRuns(); got != 64 {
		t.Errorf("at ceiling: %d, want 64", got)
	}
}

// --- server-wide attribution enforcement ---

// Attribution is enforced SERVER-SIDE for every definition. A route that says nothing about
// attribution (the common case — 12 of 17 live definitions) must still refuse an unverified event.
func TestUnattributedIsDroppedEvenWhenRouteIsSilent(t *testing.T) {
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	// NOTE: no require_attribution field at all.
	writeFile(t, emap, `[{"id":"open","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate"}]`)

	var chain bytes.Buffer
	launched := make(chan struct{}, 1)
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](&chain),
		ingressSecret: []byte("shared"),
		runEvent:      func(dispatch.Decision, dispatch.Event, ingress.Envelope) { launched <- struct{}{} },
	}

	payload := []byte(`{"id":"e1","type":"posture.drifted","source":"prooflayer"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", "deadbeef") // wrong signature
	rec := httptest.NewRecorder()
	s.webhook(rec, req)

	if !strings.Contains(rec.Body.String(), "dropped:unattributed") {
		t.Errorf("an unverified event dispatched on a route that never opted in: %s", rec.Body.String())
	}
	select {
	case <-launched:
		t.Error("a governed run was launched for an unattributed event")
	case <-time.After(100 * time.Millisecond):
	}
	if !strings.Contains(chain.String(), "dropped:unattributed") {
		t.Error("the refusal was not recorded")
	}
}

// The zero-value Server must be CLOSED. A bool phrased as `requireAttribution` would default to
// false in every struct literal — the exact trap this replaced.
func TestZeroValueServerRequiresAttribution(t *testing.T) {
	var s Server
	if s.allowUnattributed {
		t.Fatal("the zero-value Server allows unattributed events — the safe state must be the default")
	}
}

// The escape hatch works, and is the only way an unverified event dispatches.
func TestAllowUnattributedOpensTheDoor(t *testing.T) {
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"open","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate"}]`)

	launched := make(chan struct{}, 1)
	s := &Server{
		eventMap:          emap,
		ingressChain:      egress.NewChain[ingress.Record](new(bytes.Buffer)),
		ingressSecret:     []byte("shared"),
		allowUnattributed: true,
		runEvent:          func(dispatch.Decision, dispatch.Event, ingress.Envelope) { launched <- struct{}{} },
	}

	payload := []byte(`{"id":"e1","type":"posture.drifted","source":"prooflayer"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", "deadbeef")
	s.webhook(httptest.NewRecorder(), req)

	select {
	case <-launched:
	case <-time.After(2 * time.Second):
		t.Fatal("-ingress-allow-unattributed did not dispatch an unverified event")
	}
}

// A correctly signed event still dispatches — the enforcement must not break the happy path.
func TestAttributedStillDispatches(t *testing.T) {
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"open","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate"}]`)

	secret := []byte("shared")
	launched := make(chan struct{}, 1)
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](new(bytes.Buffer)),
		ingressSecret: secret,
		runEvent:      func(dispatch.Decision, dispatch.Event, ingress.Envelope) { launched <- struct{}{} },
	}

	payload := []byte(`{"id":"e1","type":"posture.drifted","source":"prooflayer"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
	s.webhook(httptest.NewRecorder(), req)

	select {
	case <-launched:
	case <-time.After(2 * time.Second):
		t.Fatal("a properly signed event did not dispatch")
	}
}

// --- single-flight per recipe ---
//
// Measured on the live instance: the kube watcher and the cilium deny aggregator both dispatched
// k8s_network_fix for ONE incident (symptom and cause). Two senders, two processes, two debounce
// keys, neither able to see the other. Collapsing that is the harness's job.

// sfServer builds a front door whose two event-map entries route DIFFERENT events to the SAME
// recipe — the correlated-storm shape.
func sfServer(t *testing.T, run func(dispatch.Decision, dispatch.Event, ingress.Envelope)) (*Server, *bytes.Buffer, []byte) {
	t.Helper()
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[
	  {"id":"symptom","match":{"source":"kube","type":"unreachable"},"recipe":"net_fix"},
	  {"id":"cause","match":{"source":"cilium","type":"denies"},"recipe":"net_fix"},
	  {"id":"other","match":{"source":"kube","type":"disk"},"recipe":"disk_fix"}
	]`)
	var chain bytes.Buffer
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](&chain),
		ingressSecret: []byte("shared"),
		runEvent:      run,
		inFlight:      make(map[string]bool),
	}
	return s, &chain, []byte("shared")
}

func postAs(t *testing.T, s *Server, secret []byte, source, typ string) string {
	t.Helper()
	payload := []byte(`{"id":"e","type":"` + typ + `","source":"` + source + `"}`)
	req := httptest.NewRequest("POST", "/api/ingress/"+source, bytes.NewReader(payload))
	req.SetPathValue("source", source)
	req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
	rec := httptest.NewRecorder()
	s.webhook(rec, req)
	var resp struct {
		Disposition string `json:"disposition"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return resp.Disposition
}

// The measured case: two DIFFERENT senders, two DIFFERENT events, one recipe.
func TestSingleFlightCollapsesTwoSendersOnOneRecipe(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	s, chain, secret := sfServer(t, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		started <- struct{}{}
		<-release
	})

	if d := postAs(t, s, secret, "kube", "unreachable"); !strings.HasPrefix(d, "dispatched:") {
		t.Fatalf("first (symptom): %q", d)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the first run never started")
	}

	// The cilium aggregator reports the CAUSE of the same incident.
	if d := postAs(t, s, secret, "cilium", "denies"); d != "dropped:already-running" {
		t.Errorf("second sender on the same recipe: %q, want dropped:already-running", d)
	}
	select {
	case <-started:
		t.Error("a second run started for a recipe already working")
	case <-time.After(100 * time.Millisecond):
	}

	// Both reports are RECORDED — the audit shows the collapse, it is not silent.
	if !strings.Contains(chain.String(), "dropped:already-running") {
		t.Error("the collapsed event was not recorded")
	}
	close(release)
}

// A DIFFERENT recipe is unaffected — this bounds duplicate work, not throughput.
func TestSingleFlightDoesNotBlockOtherRecipes(t *testing.T) {
	release := make(chan struct{})
	started := make(chan string, 4)
	s, _, secret := sfServer(t, func(dec dispatch.Decision, _ dispatch.Event, _ ingress.Envelope) {
		started <- dec.RecipeID
		<-release
	})

	postAs(t, s, secret, "kube", "unreachable") // claims net_fix
	<-started
	if d := postAs(t, s, secret, "kube", "disk"); !strings.HasPrefix(d, "dispatched:") {
		t.Errorf("an unrelated recipe was blocked: %q", d)
	}
	select {
	case r := <-started:
		if r != "disk_fix" {
			t.Errorf("started %q, want disk_fix", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the unrelated recipe never ran")
	}
	close(release)
}

// The claim is released when the run finishes, so a LATER incident on the same recipe runs.
func TestSingleFlightReleasesOnCompletion(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 4)
	s, _, secret := sfServer(t, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		started <- struct{}{}
		<-gate
	})

	postAs(t, s, secret, "kube", "unreachable")
	<-started
	close(gate) // let it finish

	deadline := time.After(2 * time.Second)
	for {
		if d := postAs(t, s, secret, "cilium", "denies"); strings.HasPrefix(d, "dispatched:") {
			<-started
			return
		}
		select {
		case <-deadline:
			t.Fatal("the recipe stayed claimed after its run finished")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// A panicking run must release its claim, or that recipe never runs again.
func TestSingleFlightSurvivesPanickingRun(t *testing.T) {
	done := make(chan struct{}, 4)
	var calls atomic.Int32
	s, _, secret := sfServer(t, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		defer func() { done <- struct{}{} }()
		defer func() { _ = recover() }()
		if calls.Add(1) == 1 {
			panic("boom")
		}
	})

	postAs(t, s, secret, "kube", "unreachable")
	<-done
	time.Sleep(50 * time.Millisecond)

	if d := postAs(t, s, secret, "cilium", "denies"); !strings.HasPrefix(d, "dispatched:") {
		t.Errorf("a panicking run leaked its claim: %q", d)
	}
	<-done
}

// Shedding at the cap must not leave a claim behind — the run never happened.
func TestSingleFlightClaimReleasedWhenShedAtCap(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	s, _, secret := sfServer(t, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		started <- struct{}{}
		<-release
	})
	s.runSem = make(chan struct{}, 1) // cap of one

	postAs(t, s, secret, "kube", "unreachable") // fills the cap, claims net_fix
	<-started

	// disk_fix is a different recipe (claims fine) but the CAP is full -> shed.
	if d := postAs(t, s, secret, "kube", "disk"); d != "dropped:at-capacity" {
		t.Fatalf("expected the cap to shed: %q", d)
	}
	close(release)

	// Once capacity frees, disk_fix must still be claimable — its claim was released on the shed.
	deadline := time.After(2 * time.Second)
	for {
		if d := postAs(t, s, secret, "kube", "disk"); strings.HasPrefix(d, "dispatched:") {
			return
		}
		select {
		case <-deadline:
			t.Fatal("a shed event leaked its single-flight claim")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Concurrent duplicates: exactly one wins.
func TestSingleFlightUnderConcurrentDuplicates(t *testing.T) {
	release := make(chan struct{})
	var starts atomic.Int32
	s, _, secret := sfServer(t, func(dispatch.Decision, dispatch.Event, ingress.Envelope) {
		starts.Add(1)
		<-release
	})

	var wg sync.WaitGroup
	var dispatched atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src, typ := "kube", "unreachable"
			if i%2 == 1 {
				src, typ = "cilium", "denies"
			}
			if strings.HasPrefix(postAs(t, s, secret, src, typ), "dispatched:") {
				dispatched.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if got := dispatched.Load(); got != 1 {
		t.Errorf("%d events dispatched for one recipe under concurrency, want exactly 1", got)
	}
	close(release)
	t.Logf("16 concurrent events (2 senders, 1 recipe): %d dispatched, %d run(s) started",
		dispatched.Load(), starts.Load())
}
