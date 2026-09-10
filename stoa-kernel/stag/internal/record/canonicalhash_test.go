package record_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/record"
)

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func TestCanonicalHash(t *testing.T) {
	// stability: same content, different literal order
	h1, err := record.CanonicalHash(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := record.CanonicalHash(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("stability: %q != %q", h1, h2)
	}
	// hashing the same map twice agrees (independent of Go's map iteration order)
	m := map[string]any{"x": 1, "y": 2, "z": 3}
	ma, _ := record.CanonicalHash(m)
	mb, _ := record.CanonicalHash(m)
	if ma != mb {
		t.Errorf("determinism: repeated hash differs")
	}

	// nested stability
	n1, _ := record.CanonicalHash(map[string]any{"o": map[string]any{"a": 1, "b": 2}})
	n2, _ := record.CanonicalHash(map[string]any{"o": map[string]any{"b": 2, "a": 1}})
	if n1 != n2 {
		t.Errorf("nested stability: %q != %q", n1, n2)
	}

	// sensitivity
	base, _ := record.CanonicalHash(map[string]any{"a": 1})
	if v, _ := record.CanonicalHash(map[string]any{"a": 2}); v == base {
		t.Errorf("sensitivity: changed value hashed same")
	}
	if v, _ := record.CanonicalHash(map[string]any{"a": 1, "b": 2}); v == base {
		t.Errorf("sensitivity: added key hashed same")
	}

	// format + definition
	if !isHex64(h1) {
		t.Errorf("format: %q not 64 lowercase hex", h1)
	}
	cj, err := record.CanonicalJSON(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cj)
	if h1 != hex.EncodeToString(sum[:]) {
		t.Errorf("definition: hash != hex(sha256(canonicalJSON))")
	}
	// sorted-key output pinned directly (not merely deterministic)
	if got, _ := record.CanonicalJSON(map[string]any{"b": 2, "a": 1}); string(got) != `{"a":1,"b":2}` {
		t.Errorf("CanonicalJSON keys not sorted: %s", got)
	}

	// deep nesting: keys sorted at every level
	d1, _ := record.CanonicalHash(map[string]any{"z": map[string]any{"q": map[string]any{"a": 1, "b": 2}}})
	d2, _ := record.CanonicalHash(map[string]any{"z": map[string]any{"q": map[string]any{"b": 2, "a": 1}}})
	if d1 != d2 {
		t.Errorf("deep nested stability: %q != %q", d1, d2)
	}

	// arrays are order-sensitive (json does not sort slices)
	a1, _ := record.CanonicalHash(map[string]any{"a": []any{1, 2, 3}})
	a2, _ := record.CanonicalHash(map[string]any{"a": []any{1, 2, 3}})
	aRev, _ := record.CanonicalHash(map[string]any{"a": []any{3, 2, 1}})
	if a1 != a2 || a1 == aRev {
		t.Errorf("array order: stable=%v sensitive=%v", a1 == a2, a1 != aRev)
	}

	// nil vs zero vs absent are all distinct
	hNil, _ := record.CanonicalHash(map[string]any{"x": nil})
	hZero, _ := record.CanonicalHash(map[string]any{"x": 0})
	hAbsent, _ := record.CanonicalHash(map[string]any{})
	if hNil == hZero || hNil == hAbsent || hZero == hAbsent {
		t.Errorf("nil/zero/absent must differ")
	}

	// numeric coercion: int(1) and float64(1.0) canonicalize identically ("1")
	hInt, _ := record.CanonicalHash(map[string]any{"n": 1})
	hFloat, _ := record.CanonicalHash(map[string]any{"n": 1.0})
	if hInt != hFloat {
		t.Errorf("int(1) and float64(1.0) should hash identically")
	}

	// error / fail closed, uniform across unmarshalable types
	for _, bad := range []any{make(chan int), func() {}} {
		if h, err := record.CanonicalHash(bad); err == nil || h != "" {
			t.Errorf("error case %T: got (%q, %v)", bad, h, err)
		}
	}
}

func FuzzCanonicalHash(f *testing.F) {
	f.Add("a", "b", int64(1), true)
	f.Add("k", "j", int64(0), false)
	f.Add("x", "y", int64(-5), true)
	f.Fuzz(func(t *testing.T, k1, k2 string, n int64, b bool) {
		if k1 == k2 {
			return
		}
		// mixed value types: int64, string, bool, nested map, slice.
		m := map[string]any{k1: n, k2: "x", "flag": b, "nest": map[string]any{"p": 1, "q": "y"}, "list": []any{1, "z", b}}
		h1, err := record.CanonicalHash(m)
		if err != nil {
			t.Fatal(err)
		}
		// stability: Go re-randomizes map iteration each marshal; sorted output must match.
		if h2, _ := record.CanonicalHash(m); h2 != h1 {
			t.Errorf("STABILITY: repeated hash differs")
		}
		if len(h1) != 64 {
			t.Errorf("format: len(hash) = %d, want 64", len(h1))
		}
		// sensitivity: change one field -> different hash.
		if m[k2] != any("CHANGED-VALUE-Z") {
			m[k2] = "CHANGED-VALUE-Z"
			if h3, _ := record.CanonicalHash(m); h3 == h1 {
				t.Errorf("SENSITIVITY: value change did not change hash")
			}
		}
	})
}
