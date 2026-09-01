package egress_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

// ev builds one audit leaf: an ALLOWED decision carrying the crossing it released. (The chain's unit is
// the decision; a release rides inside it, and only ever on a forwarded call.)
func ev(i int, field string) stag.DecisionRecord {
	return stag.DecisionRecord{
		Tool:       "write_note",
		Verdict:    "allow",
		Forwarded:  true,
		Value:      field,
		Recipe:     "write_note_policy",
		RecipeHash: "f88a9c15",
		Events: []stag.ReleaseEvent{{
			SubjectOrigin:   "propose",
			CollectedField:  "action",
			TargetField:     field,
			AuthorizingRule: fmt.Sprintf("rule.%d", i),
			Actor:           "policy:incident",
			Ordering:        int64(i),
			RecipeHash:      "f88a9c15",
		}},
	}
}

// failWriter errors on the (okN+1)th write.
type failWriter struct {
	buf *bytes.Buffer
	ok  int
	n   int
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.ok {
		return 0, errors.New("disk full")
	}
	return w.buf.Write(p)
}

func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestRecordAndVerify(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	s := egress.NewJSONLSink(&buf)
	events := []stag.DecisionRecord{ev(0, "a"), ev(1, "b"), ev(2, "c")}
	for _, e := range events {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	res, err := egress.Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("honest log must verify: %v", err)
	}
	if res.Count != 3 || res.Head != s.Head() {
		t.Errorf("verify: %+v sinkHead=%s sinkCount=%d", res, s.Head(), s.Count())
	}

	ls := lines(buf.Bytes())
	if len(ls) != 3 {
		t.Fatalf("want 3 lines, got %d", len(ls))
	}
	var l0, l1 egress.Leaf
	mustJSON(t, ls[0], &l0)
	mustJSON(t, ls[1], &l1)
	if l0.Seq != 0 || l0.PrevHash != egress.GenesisHash {
		t.Errorf("leaf 0: seq=%d prev=%q", l0.Seq, l0.PrevHash)
	}
	if l1.PrevHash != l0.Hash {
		t.Errorf("chain: leaf1.prev %q != leaf0.hash %q", l1.PrevHash, l0.Hash)
	}

	// empty sink
	var eb bytes.Buffer
	es := egress.NewJSONLSink(&eb)
	r2, err := egress.Verify(bytes.NewReader(eb.Bytes()))
	if err != nil || r2.Head != egress.GenesisHash || r2.Count != 0 {
		t.Errorf("empty log: %+v err=%v (head should be genesis, count 0)", r2, err)
	}
	_ = es
}

func TestVerifyRejectsTamper(t *testing.T) {
	ctx := context.Background()
	honest := func() []byte {
		var buf bytes.Buffer
		s := egress.NewJSONLSink(&buf)
		for _, e := range []stag.DecisionRecord{ev(0, "a"), ev(1, "b"), ev(2, "c")} {
			if err := s.Record(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		return buf.Bytes()
	}
	// sanity: the honest log verifies
	if _, err := egress.Verify(bytes.NewReader(honest())); err != nil {
		t.Fatalf("honest log must verify: %v", err)
	}

	cases := map[string]func(ls []string) []byte{
		"edit event field": func(ls []string) []byte {
			// ReleaseEvent has no json tags, so the stored key is the Go field name.
			ls[1] = strings.Replace(ls[1], `"TargetField":"b"`, `"TargetField":"X"`, 1)
			return []byte(strings.Join(ls, "\n") + "\n")
		},
		"rewrite hash": func(ls []string) []byte {
			var l0, l1 egress.Leaf
			_ = json.Unmarshal([]byte(ls[0]), &l0)
			_ = json.Unmarshal([]byte(ls[1]), &l1)
			l1.Hash = l0.Hash
			b, _ := json.Marshal(l1)
			ls[1] = string(b)
			return []byte(strings.Join(ls, "\n") + "\n")
		},
		"reorder": func(ls []string) []byte {
			ls[1], ls[2] = ls[2], ls[1]
			return []byte(strings.Join(ls, "\n") + "\n")
		},
		"drop": func(ls []string) []byte {
			return []byte(ls[0] + "\n" + ls[2] + "\n")
		},
		"insert dup": func(ls []string) []byte {
			return []byte(ls[0] + "\n" + ls[1] + "\n" + ls[1] + "\n" + ls[2] + "\n")
		},
		"garbage line": func(ls []string) []byte {
			ls[1] = "{ not json"
			return []byte(strings.Join(ls, "\n") + "\n")
		},
		"leaf0 prev changed": func(ls []string) []byte {
			var l0 egress.Leaf
			_ = json.Unmarshal([]byte(ls[0]), &l0)
			l0.PrevHash = "deadbeef"
			b, _ := json.Marshal(l0)
			ls[0] = string(b)
			return []byte(strings.Join(ls, "\n") + "\n")
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			bad := mut(lines(honest()))
			if _, err := egress.Verify(bytes.NewReader(bad)); err == nil {
				t.Errorf("tampered log (%s) must NOT verify", name)
			}
		})
	}
}

func TestWriteErrorFailClosed(t *testing.T) {
	ctx := context.Background()
	fw := &failWriter{buf: &bytes.Buffer{}, ok: 1} // 1st write ok, 2nd fails
	s := egress.NewJSONLSink(fw)

	if err := s.Record(ctx, ev(0, "a")); err != nil {
		t.Fatal(err)
	}
	head1, count1 := s.Head(), s.Count()
	if count1 != 1 || head1 == egress.GenesisHash {
		t.Fatalf("after record 1: head=%q count=%d", head1, count1)
	}

	if err := s.Record(ctx, ev(1, "b")); err == nil {
		t.Error("record over failing writer must return an error")
	}
	if s.Head() != head1 || s.Count() != count1 {
		t.Errorf("failed write must not advance: head=%q count=%d (want %q,%d)", s.Head(), s.Count(), head1, count1)
	}

	// writer works again: the chain continues from head1, not a broken state
	fw.ok = 100
	if err := s.Record(ctx, ev(1, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := egress.Verify(bytes.NewReader(fw.buf.Bytes())); err != nil {
		t.Errorf("chain after recovery must verify: %v", err)
	}
	if s.Count() != 2 {
		t.Errorf("count after recovery: %d", s.Count())
	}
}

func TestResume(t *testing.T) {
	ctx := context.Background()
	var a bytes.Buffer
	sa := egress.NewJSONLSink(&a)
	for _, e := range []stag.DecisionRecord{ev(0, "a"), ev(1, "b")} {
		if err := sa.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	pre, err := egress.Verify(bytes.NewReader(a.Bytes()))
	if err != nil || pre.Count != 2 {
		t.Fatalf("prefix verify: %+v err=%v", pre, err)
	}

	var b bytes.Buffer
	sb := egress.ResumeJSONLSink(&b, pre.Head, pre.Count)
	if err := sb.Record(ctx, ev(2, "c")); err != nil {
		t.Fatal(err)
	}

	full := append(append([]byte{}, a.Bytes()...), b.Bytes()...)
	res, err := egress.Verify(bytes.NewReader(full))
	if err != nil {
		t.Fatalf("resumed chain must verify: %v", err)
	}
	if res.Count != 3 || res.Head != sb.Head() {
		t.Errorf("resumed verify: %+v sinkHead=%s", res, sb.Head())
	}
	// B alone is a continuation (first leaf seq 2), not a standalone chain
	if _, err := egress.Verify(bytes.NewReader(b.Bytes())); err == nil {
		t.Error("continuation segment must not verify standalone")
	}
}

func mustJSON(t *testing.T, line string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(line), v); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
}

func FuzzChainIntegrity(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add([]byte{1, 'x'}, uint16(0))
	f.Add([]byte{3, 'a', 'b', 'c'}, uint16(7))
	f.Add([]byte{5, 0xff, 0xfe, 0x00, '\n', '"'}, uint16(42))
	f.Fuzz(func(t *testing.T, data []byte, pos uint16) {
		ctx := context.Background()
		events := eventsFromBytes(data)

		var buf bytes.Buffer
		s := egress.NewJSONLSink(&buf)
		for _, e := range events {
			if err := s.Record(ctx, e); err != nil {
				t.Fatalf("record: %v", err)
			}
		}

		// (1) honest log verifies; head + count match the sink
		res, err := egress.Verify(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("honest log must verify: %v", err)
		}
		if res.Head != s.Head() || res.Count != int64(len(events)) {
			t.Fatalf("verify %+v != sink head=%s count=%d", res, s.Head(), s.Count())
		}

		// (2) determinism
		var buf2 bytes.Buffer
		s2 := egress.NewJSONLSink(&buf2)
		for _, e := range events {
			_ = s2.Record(ctx, e)
		}
		if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
			t.Fatalf("nondeterministic output")
		}

		// (3) flip ANY single byte -> Verify must reject
		if b := buf.Bytes(); len(b) > 0 {
			i := int(pos) % len(b)
			tampered := make([]byte, len(b))
			copy(tampered, b)
			tampered[i] ^= 0xFF
			if _, err := egress.Verify(bytes.NewReader(tampered)); err == nil {
				t.Fatalf("CHAIN-INTEGRITY BREACH: flip of byte %d not detected\n%q", i, tampered)
			}
		}
	})
}

// eventsFromBytes builds 0..5 events with fields varied by the fuzz input,
// including arbitrary/invalid-UTF8 bytes to exercise canonical hashing.
func eventsFromBytes(data []byte) []stag.DecisionRecord {
	if len(data) == 0 {
		return nil
	}
	n := int(data[0]) % 6
	frag := ""
	if len(data) > 1 {
		frag = string(data[1:])
	}
	out := make([]stag.DecisionRecord, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, stag.DecisionRecord{
			Tool:       fmt.Sprintf("tool%d", i),
			Verdict:    "allow",
			Forwarded:  true,
			Value:      frag,
			RecipeHash: frag,
			Events: []stag.ReleaseEvent{{
				SubjectOrigin:   "propose",
				CollectedField:  "action",
				TargetField:     fmt.Sprintf("t%d/%s", i, frag),
				AuthorizingRule: fmt.Sprintf("r%d/%s", i, frag),
				Actor:           "policy:incident",
				Ordering:        int64(i),
				RecipeHash:      frag,
			}},
		})
	}
	return out
}
