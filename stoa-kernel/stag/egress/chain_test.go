package egress_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

// A chained read log verifies clean, and every leaf attests the exact content the model saw.
func TestReadChainAppendsAndVerifies(t *testing.T) {
	var buf bytes.Buffer
	ch := egress.NewChain[provider.ReadEvent](&buf)

	reads := []provider.ReadEvent{
		{Provider: "runbooks", Query: "eu outage", Items: 1, ItemHashes: []string{provider.HashText("runbook A")}},
		{Provider: "runbooks", Query: "scale", Items: 2, ItemHashes: []string{provider.HashText("a"), provider.HashText("b")}},
	}
	for _, r := range reads {
		if err := ch.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	res, err := egress.VerifyChain[provider.ReadEvent](bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Count != 2 || res.Head != ch.Head() {
		t.Fatalf("verify head/count mismatch: %+v vs head=%s count=%d", res, ch.Head(), ch.Count())
	}
}

// Tampering with a recorded read is DETECTED: flip a byte in the stored content-hash and verify
// fails. This is the property that makes "what the model read" evidence, not a mutable note.
func TestReadChainDetectsTamper(t *testing.T) {
	var buf bytes.Buffer
	ch := egress.NewChain[provider.ReadEvent](&buf)
	_ = ch.Append(provider.ReadEvent{Provider: "kb", Query: "q", Items: 1, ItemHashes: []string{provider.HashText("the fact the model saw")}})

	// rewrite the item hash (as if an operator edited what was read after the fact)
	tampered := strings.Replace(buf.String(), provider.HashText("the fact the model saw"), provider.HashText("a different fact"), 1)
	if tampered == buf.String() {
		t.Fatal("test setup: nothing was replaced")
	}
	if _, err := egress.VerifyChain[provider.ReadEvent](strings.NewReader(tampered)); err == nil {
		t.Fatal("a rewritten read record must fail verification")
	}
}

// A dropped/reordered leaf breaks the chain (sequence + prev-hash linkage).
func TestReadChainDetectsDroppedLeaf(t *testing.T) {
	var buf bytes.Buffer
	ch := egress.NewChain[provider.ReadEvent](&buf)
	for i := 0; i < 3; i++ {
		_ = ch.Append(provider.ReadEvent{Provider: "kb", Query: "q", Items: 0})
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// drop the middle leaf
	broken := lines[0] + "\n" + lines[2] + "\n"
	if _, err := egress.VerifyChain[provider.ReadEvent](strings.NewReader(broken)); err == nil {
		t.Fatal("a dropped leaf must break the chain")
	}
}

// The read-event hash is content-addressed: the query, items, and per-item hashes all move it.
func TestReadEventHashContentAddressed(t *testing.T) {
	base := provider.ReadEvent{Provider: "kb", Query: "q", Items: 1, ItemHashes: []string{provider.HashText("x")}}
	h0, _ := base.Hash()

	same := base
	hs, _ := same.Hash()
	if h0 != hs {
		t.Fatal("identical read events must hash the same")
	}
	diff := base
	diff.ItemHashes = []string{provider.HashText("y")} // different content read
	hd, _ := diff.Hash()
	if h0 == hd {
		t.Fatal("different read content must change the hash")
	}
}

// The outbound query is bounded: a huge query is capped and flagged, so `?q` cannot be an
// unbounded exfiltration channel.
func TestBoundQuery(t *testing.T) {
	small, tr := provider.BoundQuery("hello")
	if small != "hello" || tr {
		t.Fatalf("a short query must pass unchanged: %q %v", small, tr)
	}
	big := strings.Repeat("A", provider.MaxQueryLen*3)
	capped, tr := provider.BoundQuery(big)
	if !tr || len(capped) > provider.MaxQueryLen {
		t.Fatalf("a long query must be capped and flagged: len=%d truncated=%v", len(capped), tr)
	}
}
