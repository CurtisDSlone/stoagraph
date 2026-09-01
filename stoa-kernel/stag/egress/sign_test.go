package egress_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

func fixedKey(t testing.TB, b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{b}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// logOf records events to a buffer and returns the bytes plus a Checkpoint over
// the head. ctx-free: the sink ignores ctx.
func logOf(t testing.TB, origin string, events ...stag.DecisionRecord) ([]byte, egress.Checkpoint) {
	t.Helper()
	var buf bytes.Buffer
	s := egress.NewJSONLSink(&buf)
	for _, e := range events {
		if err := s.Record(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes(), egress.Checkpoint{Origin: origin, Count: s.Count(), Head: s.Head()}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := fixedKey(t, 1)
	log, cp := logOf(t, "stag/test", ev(0, "a"), ev(1, "b"), ev(2, "c"))
	sc := egress.Sign(priv, cp)

	if sc.KeyID != egress.KeyID(pub) {
		t.Errorf("key id: %q != %q", sc.KeyID, egress.KeyID(pub))
	}
	res, err := egress.VerifySigned(pub, sc, bytes.NewReader(log))
	if err != nil {
		t.Fatalf("honest signed log must verify: %v", err)
	}
	if res.Count != 3 || res.Head != cp.Head {
		t.Errorf("verify: %+v", res)
	}
	// deterministic
	if sc2 := egress.Sign(priv, cp); sc2.Sig != sc.Sig {
		t.Errorf("Ed25519 signing must be deterministic")
	}
}

func TestVerifySignedFailsClosed(t *testing.T) {
	pub, priv := fixedKey(t, 2)
	otherPub, _ := fixedKey(t, 9)
	log, cp := logOf(t, "o", ev(0, "a"), ev(1, "b"))
	good := egress.Sign(priv, cp)

	flipSig := func(sc egress.SignedCheckpoint) egress.SignedCheckpoint {
		raw, _ := base64.StdEncoding.DecodeString(sc.Sig)
		raw[0] ^= 0xFF
		sc.Sig = base64.StdEncoding.EncodeToString(raw)
		return sc
	}

	cases := map[string]func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey){
		"tampered log": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			b := append([]byte{}, log...)
			b[20] ^= 0xFF
			return good, b, pub
		},
		"count bumped": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			sc := good
			sc.Count++
			return sc, log, pub
		},
		"head changed": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			sc := good
			sc.Head = "deadbeef"
			return sc, log, pub
		},
		"sig flipped": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) { return flipSig(good), log, pub },
		"sig junk": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			sc := good
			sc.Sig = "not base64!!"
			return sc, log, pub
		},
		"wrong key": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) { return good, log, otherPub },
		"keyid changed": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			sc := good
			sc.KeyID = "0011223344556677"
			return sc, log, pub
		},
		"malformed pub": func() (egress.SignedCheckpoint, []byte, ed25519.PublicKey) {
			return good, log, ed25519.PublicKey{1, 2, 3}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			sc, l, p := mk()
			if _, err := egress.VerifySigned(p, sc, bytes.NewReader(l)); err == nil {
				t.Errorf("%s must fail closed", name)
			}
		})
	}
}

func TestKeyMarshalRoundTrip(t *testing.T) {
	pub, priv, err := egress.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := egress.ParsePrivate(egress.MarshalPrivate(priv))
	if err != nil || !priv.Equal(priv2) {
		t.Fatalf("private round-trip: err=%v equal=%v", err, priv.Equal(priv2))
	}
	pub2, err := egress.ParsePublic(egress.MarshalPublic(pub))
	if err != nil || !pub.Equal(pub2) {
		t.Fatalf("public round-trip: err=%v equal=%v", err, pub.Equal(pub2))
	}
	// the round-tripped keys still sign/verify
	log, cp := logOf(t, "o", ev(0, "a"))
	if _, err := egress.VerifySigned(pub2, egress.Sign(priv2, cp), bytes.NewReader(log)); err != nil {
		t.Errorf("round-tripped keys must still verify: %v", err)
	}
	// fail closed on junk
	if _, err := egress.ParsePrivate([]byte("short")); err == nil {
		t.Error("ParsePrivate must reject truncated input")
	}
	if _, err := egress.ParsePublic([]byte("!!!not base64!!!")); err == nil {
		t.Error("ParsePublic must reject invalid encoding")
	}
}

func FuzzSignedCheckpoint(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add([]byte{1, 'x'}, uint16(0))
	f.Add([]byte{3, 'a', 'b'}, uint16(11))
	f.Add([]byte{5, 0xff, 0x00, '\n'}, uint16(40))
	pub, priv := fixedKey(f, 7)
	otherPub, _ := fixedKey(f, 8)

	f.Fuzz(func(t *testing.T, data []byte, pos uint16) {
		events := eventsFromBytes(data)
		log, cp := logOf(t, "stag/fuzz", events...)
		sc := egress.Sign(priv, cp)

		// (1) honest signed log verifies
		res, err := egress.VerifySigned(pub, sc, bytes.NewReader(log))
		if err != nil {
			t.Fatalf("honest signed log must verify: %v", err)
		}
		if res.Head != cp.Head || res.Count != cp.Count {
			t.Fatalf("verify %+v != cp %+v", res, cp)
		}
		// (2) determinism
		if egress.Sign(priv, cp).Sig != sc.Sig {
			t.Fatalf("nondeterministic signature")
		}
		// (3) tamper the log
		if len(log) > 0 {
			b := append([]byte{}, log...)
			b[int(pos)%len(b)] ^= 0xFF
			if _, err := egress.VerifySigned(pub, sc, bytes.NewReader(b)); err == nil {
				t.Fatalf("tampered log must reject")
			}
		}
		// (4) tamper the signature
		raw, derr := base64.StdEncoding.DecodeString(sc.Sig)
		if derr != nil || len(raw) == 0 {
			t.Fatalf("signature must be valid base64: %v", derr)
		}
		bad := sc
		ts := append([]byte{}, raw...)
		ts[int(pos)%len(ts)] ^= 0xFF
		bad.Sig = base64.StdEncoding.EncodeToString(ts)
		if _, err := egress.VerifySigned(pub, bad, bytes.NewReader(log)); err == nil {
			t.Fatalf("tampered signature must reject")
		}
		// (5) wrong key
		if _, err := egress.VerifySigned(otherPub, sc, bytes.NewReader(log)); err == nil {
			t.Fatalf("wrong key must reject")
		}
	})
}
