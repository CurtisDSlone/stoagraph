// Command stag-verify replays a hash-chained stag audit log and reports whether the chain is INTACT —
// the "verify the audit yourself" half of verifiable control. It recomputes every leaf hash and the
// prev-hash links; tampering with, reordering, or dropping any leaf fails the check. On success it
// prints the record sequence the log attests, so a human reads the story, not just a checkmark.
//
// THREE LOG SHAPES, because two different chain implementations exist (egress.go's original,
// DecisionRecord-only Leaf, and chain.go's later generic Chain[T] — see chain.go's own comment on
// why: the decision log's shape predates the generic one and existing logs depend on it, so it was
// never migrated). decisions.jsonl uses the old shape (`"decision"`); reads.jsonl and ingress.jsonl
// use the new one (`"record"`), with the record's own fields telling them apart. This command
// sniffs the first leaf and picks the matching verifier — a wrong guess would deny the operator the
// "verify the ENTIRE audit surface yourself" ability the product's non-negotiables promise, silently
// narrowed to "verify the decision log", which is not the same claim.
//
//	stag-verify data/decisions.jsonl
//	stag-verify data/reads.jsonl
//	stag-verify data/ingress.jsonl
//	stag-verify -pub operator.pub.key -checkpoint data/checkpoint.json data/decisions.jsonl
package main

// file-kw: cli verify audit chain tamper-evident replay leaves allow deny escalate signed checkpoint session-column policy-column interleaved-runs which-agent which-policy-version generic-chain reads-log ingress-log three-shapes sniff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/ingress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

func main() {
	pubPath := flag.String("pub", "", "Ed25519 public key file to verify a signed checkpoint (optional)")
	ckptPath := flag.String("checkpoint", "", "signed checkpoint file to verify against -pub (optional)")
	quiet := flag.Bool("quiet", false, "print only the PASS/FAIL line, not the decision sequence")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: stag-verify [-pub KEY -checkpoint FILE] [-quiet] <log.jsonl>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "stag-verify: %v\n", err)
		os.Exit(2)
	}

	kind, sniffErr := sniffKind(raw)
	if sniffErr != nil {
		fmt.Printf("CHAIN BROKEN — %v\n", sniffErr)
		os.Exit(1)
	}

	var res egress.VerifyResult
	switch kind {
	case kindDecision:
		res, err = egress.Verify(bytes.NewReader(raw))
	case kindIngress:
		res, err = egress.VerifyChain[ingress.Record](bytes.NewReader(raw))
	case kindRead:
		res, err = egress.VerifyChain[provider.ReadEvent](bytes.NewReader(raw))
	}
	if err != nil {
		fmt.Printf("CHAIN BROKEN — %v\n", err)
		os.Exit(1)
	}
	head := res.Head
	if len(head) > 16 {
		head = head[:16]
	}
	fmt.Printf("CHAIN INTACT — %s, %d leaf/leaves, head %s…\n", kind.label(), res.Count, head)

	if !*quiet {
		fmt.Println()
		switch kind {
		case kindDecision:
			printDecisionLeaves(raw)
		case kindIngress:
			printIngressLeaves(raw)
		case kindRead:
			printReadLeaves(raw)
		}
	}

	// Optional: verify a signed checkpoint proves this exact head under the operator's key.
	if *pubPath != "" && *ckptPath != "" {
		if err := verifySigned(*pubPath, *ckptPath, raw); err != nil {
			fmt.Printf("\nSIGNATURE INVALID — %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\nSIGNATURE VALID — the operator's key attests this head")
	}
}

// logKind names which of the three leaf shapes a log holds. See the package doc comment for why
// there are three: one hand-written (decisions.jsonl) and two built on the later generic chain.
type logKind int

const (
	kindDecision logKind = iota // egress.Leaf   — {"decision": DecisionRecord, ...}
	kindIngress                 // genLeaf[ingress.Record]  — {"record": {"disposition": ..., "source": ...}, ...}
	kindRead                    // genLeaf[provider.ReadEvent] — {"record": {"provider": ..., "query": ...}, ...}
)

func (k logKind) label() string {
	switch k {
	case kindIngress:
		return "ingress log"
	case kindRead:
		return "read log"
	default:
		return "decision log"
	}
}

// sniffKind reads only the FIRST leaf to decide which verifier to run. It does not decide anything
// about tampering — verification still replays every leaf under the shape it settles on — it only
// resolves the ambiguity plain JSON leaves it: "decision" is unambiguous (only the old shape uses
// that key), but "record" is used by BOTH newer log types, and only the record's OWN fields (an
// ingress record's "disposition", a read record's "provider"/"query") say which one it is. An empty
// file (no leaves to sniff) is treated as an empty decision log — CHAIN INTACT, 0 leaves — the
// harmless case for every kind alike.
func sniffKind(raw []byte) (logKind, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Decision json.RawMessage `json:"decision"`
			Record   json.RawMessage `json:"record"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return 0, fmt.Errorf("leaf 0: not a recognized leaf shape: %w", err)
		}
		switch {
		case probe.Decision != nil:
			return kindDecision, nil
		case probe.Record != nil:
			var rec struct {
				Disposition string `json:"disposition"`
				Provider    string `json:"provider"`
			}
			if err := json.Unmarshal(probe.Record, &rec); err != nil {
				return 0, fmt.Errorf("leaf 0: unrecognized record shape: %w", err)
			}
			switch {
			case rec.Disposition != "":
				return kindIngress, nil
			case rec.Provider != "":
				return kindRead, nil
			default:
				return 0, fmt.Errorf("leaf 0: a \"record\" leaf with neither \"disposition\" nor \"provider\" — an unknown log type stag-verify has no reader for")
			}
		default:
			return 0, fmt.Errorf("leaf 0: neither \"decision\" nor \"record\" — not a stag audit leaf")
		}
	}
	return kindDecision, nil // no leaves at all: an empty log, harmless under any kind
}

func printDecisionLeaves(raw []byte) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var lf egress.Leaf
		if json.Unmarshal(line, &lf) != nil {
			continue
		}
		d := lf.Decision
		verb := d.Verdict
		if d.Forwarded {
			verb += "→forwarded"
		}
		// session + policy version are what let an auditor separate interleaved runs: decisions
		// from different agents share a chain, and are otherwise identical whenever the policy is.
		row := fmt.Sprintf("  #%d  %-18s %-22s %s", lf.Seq, verb, d.Tool, d.Recipe)
		if d.Session != "" {
			row += "  session=" + short(d.Session)
		}
		if d.RecipeHash != "" {
			row += "  policy=" + short(d.RecipeHash)
		}
		if d.Value != "" {
			row += "  value=" + d.Value
		}
		if d.Fault != "" {
			row += "  reason=" + d.Fault
		}
		fmt.Println(row)
	}
}

// ingressLeaf mirrors the shape Chain[ingress.Record] writes (chain.go's genLeaf, unexported there),
// so the CLI can decode it without reaching into an internal type.
type ingressLeaf struct {
	Seq    int64          `json:"seq"`
	Record ingress.Record `json:"record"`
}

func printIngressLeaves(raw []byte) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var lf ingressLeaf
		if json.Unmarshal(line, &lf) != nil {
			continue
		}
		r := lf.Record
		row := fmt.Sprintf("  #%d  %-24s source=%-10s attributed=%-5t auth=%s",
			lf.Seq, r.Disposition, r.Source, r.Attributed, orDash(r.AuthMethod))
		fmt.Println(row)
	}
}

// readLeaf mirrors Chain[provider.ReadEvent]'s shape.
type readLeaf struct {
	Seq    int64              `json:"seq"`
	Record provider.ReadEvent `json:"record"`
}

func printReadLeaves(raw []byte) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var lf readLeaf
		if json.Unmarshal(line, &lf) != nil {
			continue
		}
		r := lf.Record
		row := fmt.Sprintf("  #%d  provider=%-14s items=%d", lf.Seq, r.Provider, r.Items)
		if r.QueryTruncated {
			row += "  QUERY-TRUNCATED"
		}
		// A read-bounds notice ("N of M returned") is the READ channel doing its job, not a
		// failure — printing it as errors=N reads as alarming for something benign. Only a notice
		// that is NOT the bounds message is a genuine read-side error.
		var genuine int
		for _, e := range r.Errors {
			if !strings.Contains(e, "read bounds") {
				genuine++
			}
		}
		if genuine > 0 {
			row += fmt.Sprintf("  errors=%d", genuine)
		} else if len(r.Errors) > 0 {
			row += "  bounded"
		}
		fmt.Println(row)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func verifySigned(pubPath, ckptPath string, log []byte) error {
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	var sc egress.SignedCheckpoint
	b, err := os.ReadFile(ckptPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &sc); err != nil {
		return err
	}
	key, err := egress.ParsePublic(bytes.TrimSpace(pub))
	if err != nil {
		return err
	}
	if _, err := egress.VerifySigned(key, sc, bytes.NewReader(log)); err != nil {
		return err
	}
	return nil
}

// short renders a digest as its first 8 hex chars — enough to distinguish sessions and policy
// versions at a glance without turning every audit row into two lines.
func short(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8]
}
