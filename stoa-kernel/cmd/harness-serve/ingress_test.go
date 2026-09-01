package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/dispatch"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

// The webhook front door, end to end (Planning/32, the I2 domino): a SIGNED event arrives over HTTP,
// the HMAC is verified (attributed), the arrival is recorded to the hash-chained ingress log, and a
// matching definition routes it to a recipe — with no model on the front door.
func TestWebhookAttributedEventDispatches(t *testing.T) {
	dir := t.TempDir()
	// an event map that routes an attributed posture.drifted to a remediation recipe.
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"drift","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate","require_attribution":true}]`)

	secret := []byte("shared")
	var logbuf bytes.Buffer
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](&logbuf),
		ingressSecret: secret,
	}

	payload := []byte(`{"id":"evt-9","type":"posture.drifted","source":"prooflayer","host":"web-01"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
	rec := httptest.NewRecorder()

	s.webhook(rec, req)

	if rec.Code != 200 {
		t.Fatalf("attributed+matched event must dispatch (200); got %d: %s", rec.Code, rec.Body)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["attributed"] != true || resp["disposition"] != "dispatched:remediate" || resp["recipe"] != "remediate" {
		t.Fatalf("unexpected response: %v", resp)
	}
	// the arrival was recorded to the hash-chained log, and it verifies.
	res, err := egress.VerifyChain[ingress.Record](bytes.NewReader(logbuf.Bytes()))
	if err != nil || res.Count != 1 {
		t.Fatalf("ingress log must have one verified leaf: count=%d err=%v", res.Count, err)
	}
}

// When an ingress model is configured (runEvent set), a matched+attributed webhook LAUNCHES the
// governed run for exactly that decision — the front door is wired through to the agent loop.
func TestWebhookTriggersGovernedRun(t *testing.T) {
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"drift","match":{"source":"prooflayer","type":"posture.drifted"},"recipe":"remediate","tools":["fix"],"context":["logs"]}]`)

	secret := []byte("shared")
	ran := make(chan dispatch.Decision, 1)
	s := &Server{
		eventMap:      emap,
		ingressChain:  egress.NewChain[ingress.Record](new(bytes.Buffer)),
		ingressSecret: secret,
		runEvent: func(dec dispatch.Decision, _ dispatch.Event, _ ingress.Envelope) {
			ran <- dec
		},
	}

	payload := []byte(`{"id":"e1","type":"posture.drifted","source":"prooflayer"}`)
	req := httptest.NewRequest("POST", "/api/ingress/prooflayer", bytes.NewReader(payload))
	req.SetPathValue("source", "prooflayer")
	req.Header.Set("X-Stag-Signature", ingress.Sign(secret, payload))
	s.webhook(httptest.NewRecorder(), req)

	select {
	case dec := <-ran:
		if dec.RecipeID != "remediate" || len(dec.Tools) != 1 || dec.Tools[0] != "fix" || len(dec.Context) != 1 {
			t.Fatalf("the run got the wrong decision: %+v", dec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a matched webhook with a model configured must launch the governed run")
	}
}

// An UNATTRIBUTED event that matches an attribution-required definition is NOT dispatched — it is
// recorded as dropped. The governing rule: attribution upgrades routing, never content.
func TestWebhookUnattributedIsNotDispatched(t *testing.T) {
	dir := t.TempDir()
	emap := filepath.Join(dir, "event_map.json")
	writeFile(t, emap, `[{"id":"drift","match":{"type":"posture.drifted"},"recipe":"remediate","require_attribution":true}]`)

	var logbuf bytes.Buffer
	s := &Server{eventMap: emap, ingressChain: egress.NewChain[ingress.Record](&logbuf), ingressSecret: []byte("shared")}

	payload := []byte(`{"type":"posture.drifted"}`)
	req := httptest.NewRequest("POST", "/api/ingress/x", bytes.NewReader(payload))
	req.SetPathValue("source", "x")
	// NO valid signature -> unattributed
	req.Header.Set("X-Stag-Signature", ingress.Sign([]byte("WRONG"), payload))
	rec := httptest.NewRecorder()

	s.webhook(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["attributed"] != false || resp["disposition"] != "dropped:unattributed" {
		t.Fatalf("an unattributed require-attribution event must be dropped, recorded: %v", resp)
	}
	if strings.Contains(rec.Body.String(), `"recipe":"remediate"`) {
		t.Fatal("an unattributed event must not report a routed recipe")
	}
	// still recorded (every arrival is evidence)
	if res, err := egress.VerifyChain[ingress.Record](bytes.NewReader(logbuf.Bytes())); err != nil || res.Count != 1 {
		t.Fatalf("the drop must still be recorded: count=%d err=%v", res.Count, err)
	}
}

// A shape failure (unparseable body) is dropped and recorded, and returns 400.
func TestWebhookShapeFailureDrops(t *testing.T) {
	var logbuf bytes.Buffer
	s := &Server{eventMap: "/nonexistent", ingressChain: egress.NewChain[ingress.Record](&logbuf), ingressSecret: []byte("k")}
	req := httptest.NewRequest("POST", "/api/ingress/x", strings.NewReader("not json"))
	req.SetPathValue("source", "x")
	rec := httptest.NewRecorder()
	s.webhook(rec, req)
	if rec.Code != 400 {
		t.Fatalf("unparseable body must 400; got %d", rec.Code)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
