package ingress_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
)

func body(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A correctly-signed delivery is ATTRIBUTED; the payload rides verbatim and the type/id are lifted.
func TestValidHMACAttributes(t *testing.T) {
	secret := []byte("shared-secret")
	a := ingress.GenericHMAC{Source: "prooflayer", Secret: secret}
	b := body(t, map[string]any{"id": "evt-1", "type": "posture.drifted", "host": "web-01"})
	sig := ingress.Sign(secret, b)

	env, err := a.Accept(map[string]string{"X-Stag-Signature": sig}, b)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !env.Attributed || env.AuthMethod != "hmac" {
		t.Fatalf("valid signature must attribute: %+v", env)
	}
	if env.Source != "prooflayer" || env.Type != "posture.drifted" || env.ID != "evt-1" {
		t.Fatalf("envelope fields wrong: %+v", env)
	}
	if string(env.Payload) != string(b) {
		t.Fatal("payload must ride VERBATIM (the bytes the gate/audit see equal what was sent)")
	}
}

// A wrong/absent signature is NOT an error — it is an UNATTRIBUTED event (still recorded, not
// dispatched by an attribution-required definition). The governing rule: no attribution, no direct
// routing; but the event is not dropped, because it may route to a validation workflow later.
func TestBadSignatureIsUnattributedNotError(t *testing.T) {
	secret := []byte("shared-secret")
	a := ingress.GenericHMAC{Source: "prooflayer", Secret: secret}
	b := body(t, map[string]any{"type": "posture.drifted"})

	// wrong signature
	env, err := a.Accept(map[string]string{"X-Stag-Signature": ingress.Sign([]byte("WRONG"), b)}, b)
	if err != nil {
		t.Fatalf("a bad signature must not error (it is an unattributed event): %v", err)
	}
	if env.Attributed {
		t.Fatal("a bad signature must NOT attribute")
	}
	// absent signature
	env2, err := a.Accept(map[string]string{}, b)
	if err != nil || env2.Attributed {
		t.Fatalf("an absent signature must be unattributed, no error: %+v err=%v", env2, err)
	}
}

// A tampered body fails verification: the signature was over the ORIGINAL bytes, so any change
// breaks attribution. This is the point of signing the raw bytes (never a re-serialization).
func TestTamperedBodyLosesAttribution(t *testing.T) {
	secret := []byte("s3cr3t")
	a := ingress.GenericHMAC{Secret: secret}
	orig := body(t, map[string]any{"type": "x", "amount": 100})
	sig := ingress.Sign(secret, orig)

	tampered := body(t, map[string]any{"type": "x", "amount": 999999})
	env, err := a.Accept(map[string]string{"X-Stag-Signature": sig}, tampered)
	if err != nil {
		t.Fatalf("tampered-but-parseable body is not a shape error: %v", err)
	}
	if env.Attributed {
		t.Fatal("a body that differs from the signed bytes must NOT attribute")
	}
}

// A non-JSON or oversize body is a SHAPE failure: dropped (error), never routed.
func TestShapeFailuresDrop(t *testing.T) {
	a := ingress.GenericHMAC{Secret: []byte("k")}
	if _, err := a.Accept(nil, []byte("not json")); err == nil {
		t.Fatal("unparseable body must drop")
	}
	if _, err := a.Accept(nil, []byte(nil)); err == nil {
		t.Fatal("empty body must drop")
	}
	big := []byte("{" + strings.Repeat(" ", ingress.MaxBody) + "}")
	if _, err := a.Accept(nil, big); err == nil {
		t.Fatal("oversize body must drop")
	}
}

// The ingress log leaf is content-addressed: same envelope + disposition => same hash; a different
// disposition (or payload) => different hash. This is what makes the front-door log evidence.
func TestIngressRecordHashIsContentAddressed(t *testing.T) {
	e := ingress.Envelope{ID: "e1", Source: "s", Type: "t", Attributed: true, AuthMethod: "hmac", Payload: []byte(`{"a":1}`)}
	h1, _ := ingress.RecordOf(e, "dispatched:foo").Hash()
	h1b, _ := ingress.RecordOf(e, "dispatched:foo").Hash()
	h2, _ := ingress.RecordOf(e, "dropped:no-route").Hash()
	if h1 != h1b {
		t.Fatal("same record must hash the same")
	}
	if h1 == h2 {
		t.Fatal("a different disposition must change the hash (the audit must see it)")
	}
}
