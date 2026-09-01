// Package ingress is the event front door (Planning/32): the quarantined adapters that turn a raw
// external delivery (an HTTP webhook today; a queue message later) into ONE canonical Envelope the
// dispatcher can route, plus the hash-chained ingress log that records every arrival.
//
// The governing rule (Planning/32): ATTRIBUTION UPGRADES ROUTING, NEVER CONTENT. An adapter may
// verify the delivery CHANNEL (an HMAC secret, a queue subscription) and mark the envelope
// Attributed — which lets a definition dispatch it directly. The PAYLOAD is always untrusted Input,
// exactly like a retrieved document: a signed webhook still quotes attacker-controlled strings.
// There is NO mechanism here to promote content; promotion happens only at the gate's sink.
//
// The listener earns no trust and holds no policy (Planning/13): it parses its transport, verifies
// its channel, and hands an envelope on. It never decides allow/deny and never fires an actuator —
// enforcement stays synchronous and sole, inside the gate.
package ingress

// file-kw: event ingress envelope adapter hmac attribution-not-content quarantined webhook log chained

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// MaxBody caps a raw delivery: an oversize body is dropped, not parsed (fail closed).
const MaxBody = 1 << 20 // 1 MiB

// Envelope is the one shape the dispatcher sees, whatever the source. The adapter fills it by
// MECHANICAL normalization (field mapping), never semantic interpretation.
type Envelope struct {
	ID         string          `json:"id"`          // source-native id if present, else a content hash
	Source     string          `json:"source"`      // the adapter/source name: "generic", "sentinel", ...
	Type       string          `json:"type"`        // normalized event type within the source
	Attributed bool            `json:"attributed"`  // channel auth verified (routable directly)
	AuthMethod string          `json:"auth_method"` // "hmac" | "none" | ...
	Payload    json.RawMessage `json:"payload"`     // the source content, VERBATIM (untrusted Input)
}

// Record is the ingress-log leaf: what arrived and what we did with it. It is hash-chained (it
// implements egress.Record) so the front door has the same tamper-evident evidence trail as the ACT
// and READ channels — "every event that arrived, and its disposition" is an auditable record, not a
// recollection. The payload is content-hashed, not stored inline, so the log does not itself become
// a copy of every untrusted body.
type Record struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Type        string `json:"type"`
	Attributed  bool   `json:"attributed"`
	AuthMethod  string `json:"auth_method"`
	PayloadHash string `json:"payload_hash"`
	Disposition string `json:"disposition"` // "dispatched" | "validated" | "dropped:<reason>" | "observed"
}

// Hash is the canonical hash of an ingress record (for the chained log).
func (r Record) Hash() (string, error) {
	return stag.CanonicalHash(map[string]any{
		"id": r.ID, "source": r.Source, "type": r.Type,
		"attributed": r.Attributed, "auth_method": r.AuthMethod,
		"payload_hash": r.PayloadHash, "disposition": r.Disposition,
	})
}

// RecordOf builds an ingress-log Record from an accepted envelope and a disposition.
func RecordOf(e Envelope, disposition string) Record {
	sum := sha256.Sum256(e.Payload)
	return Record{
		ID: e.ID, Source: e.Source, Type: e.Type, Attributed: e.Attributed,
		AuthMethod: e.AuthMethod, PayloadHash: hex.EncodeToString(sum[:]), Disposition: disposition,
	}
}

// Adapter verifies one source's channel auth and normalizes a raw delivery into an Envelope. An
// error means DROP (unparseable, oversize, or a hard failure) — a FAILED auth is NOT an error: it
// returns an envelope with Attributed=false, because an unattributed event is still an event (it may
// route to a validation workflow, Planning/32 lane 2). Only shape failures drop.
type Adapter interface {
	Name() string
	Accept(headers map[string]string, body []byte) (Envelope, error)
}

// GenericHMAC is the reference adapter: a JSON body signed with a shared secret over the raw bytes,
// carried in a header (default X-Stag-Signature: hex(HMAC-SHA256(body))). The event type is read
// from a payload field (default "type"). This is the "generic" source of Planning/32's ladder; named
// adapters (sentinel, alertmanager) are the same shape with source-specific header/field names.
type GenericHMAC struct {
	Source    string // the source name this endpoint represents
	Secret    []byte // the shared HMAC secret; empty => this endpoint cannot attribute (always unattributed)
	SigHeader string // default "X-Stag-Signature"
	TypeField string // payload field for the event type; default "type"
	IDField   string // payload field for a native id; default "id" (falls back to a content hash)
}

func (g GenericHMAC) Name() string {
	if g.Source == "" {
		return "generic"
	}
	return g.Source
}

func (g GenericHMAC) Accept(headers map[string]string, body []byte) (Envelope, error) {
	if len(body) == 0 {
		return Envelope{}, fmt.Errorf("ingress %s: empty body", g.Name())
	}
	if len(body) > MaxBody {
		return Envelope{}, fmt.Errorf("ingress %s: body too large (%d > %d)", g.Name(), len(body), MaxBody)
	}
	// Shape check FIRST: an unparseable body is dropped, never routed. Parse into a generic map so we
	// can read the type/id fields; the Payload we carry is the VERBATIM bytes, not the re-encoding.
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return Envelope{}, fmt.Errorf("ingress %s: payload is not a JSON object: %w", g.Name(), err)
	}

	// Channel attribution: verify the HMAC over the RAW bytes (never a re-serialization). A missing
	// secret or a bad/absent signature yields Attributed=false — an event, but not a routable-by-trust
	// one. Constant-time compare.
	attributed, method := false, "none"
	if len(g.Secret) > 0 {
		sig := headers[g.sigHeader()]
		if sig != "" && verifyHMAC(g.Secret, body, sig) {
			attributed, method = true, "hmac"
		}
	}

	typ := stringField(obj, orDefault(g.TypeField, "type"))
	id := stringField(obj, orDefault(g.IDField, "id"))
	if id == "" {
		sum := sha256.Sum256(body)
		id = hex.EncodeToString(sum[:8]) // stable content id when the source gives none
	}
	return Envelope{
		ID: id, Source: g.Name(), Type: typ, Attributed: attributed,
		AuthMethod: method, Payload: append([]byte(nil), body...),
	}, nil
}

func (g GenericHMAC) sigHeader() string { return orDefault(g.SigHeader, "X-Stag-Signature") }

// verifyHMAC checks a hex-encoded HMAC-SHA256 of body under secret, in constant time.
func verifyHMAC(secret, body []byte, hexSig string) bool {
	want, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// Sign is the counterpart to verifyHMAC: hex(HMAC-SHA256(body, secret)). Exported so a sender (and
// the tests) can produce a valid signature.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func stringField(obj map[string]any, key string) string {
	if v, ok := obj[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
