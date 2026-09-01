// Package egress is the v1 egress layer (rung 1 of the trust ladder, Planning/14):
// a hash-chained, tamper-evident JSONL event log behind the broker.EventSink seam,
// with NO keys and NO PKI. Each ReleaseEvent becomes one newline-delimited Leaf
// carrying its sequence, the prior leaf's hash, and its own chain hash; Verify
// reads the log back and confirms the whole chain. Tamper-evidence is RELATIVE TO
// A TRUSTED HEAD — a total rewrite by whoever controls the store is closed by the
// deferred signing + anchor rungs (delegated to the ProofLayer/Rekor connector).
package egress

// file-kw: egress jsonl hash-chain tamper-evident event log verify leaf prev-hash head no-pki eventsink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// GenesisHash is the prev_hash of the first leaf: an empty chain has no prior.
const GenesisHash = ""

const maxLeaf = 1 << 20 // 1 MiB: a single-leaf line ceiling (fail-closed on overflow)

// kw: leaf seq prev-hash event chain-hash
type Leaf struct {
	Seq      int64               `json:"seq"`
	PrevHash string              `json:"prev_hash"`
	Decision stag.DecisionRecord `json:"decision"`
	Hash     string              `json:"hash"`
}

// kw: verify result head count
type VerifyResult struct {
	Head  string
	Count int64
}

// kw: jsonl sink writer seq head chained append-only concurrent
type JSONLSink struct {
	mu   sync.Mutex
	w    io.Writer
	seq  int64
	head string
}

// kw: new jsonl sink fresh genesis
func NewJSONLSink(w io.Writer) *JSONLSink {
	return ResumeJSONLSink(w, GenesisHash, 0)
}

// kw: resume jsonl sink continue existing chain head seq
func ResumeJSONLSink(w io.Writer, head string, seq int64) *JSONLSink {
	return &JSONLSink{w: w, seq: seq, head: head}
}

// DiscardSink implements the release Sink but records NOTHING. It is for callers that EVALUATE a
// crossing without owning the audit chain — e.g. stag-serve's /api/decide, which answers "what would
// the gate decide?" without enforcing. A hash-chained log admits exactly ONE writer (the enforcement
// proxy); a second appender would fork the chain. Such callers read the log to display it and let the
// proxy be the sole writer.
type DiscardSink struct{}

// kw: discard sink record nothing simulator no audit
func (DiscardSink) Record(context.Context, stag.DecisionRecord) error { return nil }

// kw: record append chained leaf fail-closed no-advance-on-error one-leaf-per-decision
func (s *JSONLSink) Record(_ context.Context, ev stag.DecisionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize through one JSON round-trip so the event we HASH equals the event
	// we STORE equals the event Verify reads back. json.Marshal escapes invalid
	// UTF-8 as �, which decodes to a valid U+FFFD rune that re-marshals as raw
	// bytes — hashing the original would then never match the read-back. One pass
	// reaches the fixpoint (invalid UTF-8 -> U+FFFD is stable thereafter).
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("egress: marshal decision: %w", err) // fail closed
	}
	var norm stag.DecisionRecord
	if err := json.Unmarshal(raw, &norm); err != nil {
		return fmt.Errorf("egress: normalize decision: %w", err)
	}
	evHash, err := norm.Hash()
	if err != nil {
		return fmt.Errorf("egress: decision hash: %w", err)
	}
	h, err := leafHash(s.seq, s.head, evHash)
	if err != nil {
		return fmt.Errorf("egress: leaf hash: %w", err)
	}
	leaf := Leaf{Seq: s.seq, PrevHash: s.head, Decision: norm, Hash: h}
	line, err := json.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("egress: marshal: %w", err)
	}
	// the write is the last mutating step: advance head/seq ONLY after it succeeds,
	// so the in-memory chain matches exactly what was written (fail closed).
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("egress: write: %w", err)
	}
	s.head = h
	s.seq++
	return nil
}

// kw: head last leaf hash
func (s *JSONLSink) Head() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// kw: count leaves written
func (s *JSONLSink) Count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// kw: leaf hash canonical seq prev decision-hash
func leafHash(seq int64, prevHash, decisionHash string) (string, error) {
	return stag.CanonicalHash(map[string]any{
		"seq":           seq,
		"prev_hash":     prevHash,
		"decision_hash": decisionHash,
	})
}

// kw: verify chain integrity head count tamper-evident recompute
func Verify(r io.Reader) (VerifyResult, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLeaf)

	var (
		seq   int64
		prev  = GenesisHash
		count int64
	)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue // blank line: skip
		}
		// Strict decode: reject unknown/corrupted keys (a byte flip in a JSON key
		// would otherwise decode to a silently-dropped field, leaving the canonical
		// event hash unchanged and the corruption invisible) and any trailing content
		// (a flipped line delimiter joins leaves or leaves garbage after the object).
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var lf Leaf
		if err := dec.Decode(&lf); err != nil {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: decode: %w", seq, err)
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: trailing content after leaf", seq)
		}
		if lf.Seq != seq {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: seq is %d (out of order / reordered / dropped)", seq, lf.Seq)
		}
		if lf.PrevHash != prev {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: prev_hash mismatch (chain broken)", seq)
		}
		evHash, err := lf.Decision.Hash()
		if err != nil {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: decision hash: %w", seq, err)
		}
		want, err := leafHash(lf.Seq, lf.PrevHash, evHash)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: %w", seq, err)
		}
		if lf.Hash != want {
			return VerifyResult{}, fmt.Errorf("egress: leaf %d: hash mismatch (tampered)", seq)
		}
		prev = lf.Hash
		seq++
		count++
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("egress: read: %w", err)
	}
	return VerifyResult{Head: prev, Count: count}, nil
}
