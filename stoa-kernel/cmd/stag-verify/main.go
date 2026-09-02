// Command stag-verify replays a hash-chained stag audit log and reports whether the chain is INTACT —
// the "verify the audit yourself" half of verifiable control. It recomputes every leaf hash and the
// prev-hash links (egress.Verify); tampering with, reordering, or dropping any leaf fails the check.
// On success it prints the decision sequence the log attests, so a human reads the allow/deny/escalate
// story, not just a checkmark.
//
//	stag-verify data/decisions.jsonl
//	stag-verify -pub operator.pub.key -checkpoint data/checkpoint.json data/decisions.jsonl
package main

// file-kw: cli verify audit chain tamper-evident replay leaves allow deny escalate signed checkpoint session-column policy-column interleaved-runs which-agent which-policy-version

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
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

	res, err := egress.Verify(bytes.NewReader(raw))
	if err != nil {
		fmt.Printf("CHAIN BROKEN — %v\n", err)
		os.Exit(1)
	}
	head := res.Head
	if len(head) > 16 {
		head = head[:16]
	}
	fmt.Printf("CHAIN INTACT — %d leaf/leaves, head %s…\n", res.Count, head)

	if !*quiet {
		fmt.Println()
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

	// Optional: verify a signed checkpoint proves this exact head under the operator's key.
	if *pubPath != "" && *ckptPath != "" {
		if err := verifySigned(*pubPath, *ckptPath, raw); err != nil {
			fmt.Printf("\nSIGNATURE INVALID — %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\nSIGNATURE VALID — the operator's key attests this head")
	}
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
