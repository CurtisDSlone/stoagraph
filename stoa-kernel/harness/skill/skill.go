// Package skill resolves a bound skill to a TRUST SLOT (Planning/33, C3). A skill is a
// content-addressed procedure bundle; the harness verifies its ed25519 signature against the
// OPERATOR's public key and, only if it verifies, places it in the instruction (System) slot. An
// unsigned or badly-signed skill degrades to the untrusted Input slot — a lying procedure can then
// inform a proposal but never instruct the agent, and it still cannot act (every proposal hits the
// gate). This is the ClawHub failure mode (malicious marketplace skills) turned into a non-event.
//
// The load-bearing property (Planning/30 doctrine, preserved): trust comes from cryptography the
// HARNESS checks, never from a label the channel asserts. The gate serves the bytes + signature; this
// package decides the slot.
package skill

// file-kw: skill resolve verify ed25519 trust-slot system input signed unsigned tier audit clawhub

import (
	"crypto/ed25519"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/bind"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

// Tier is the trust position a resolved skill earned.
const (
	TierSigned   = "signed"   // verified against the operator key -> instruction slot
	TierUnsigned = "unsigned" // unsigned or failed verification -> Input slot (untrusted)
)

// Resolved is a skill after verification: its identity, the tier it earned, and its procedure text.
type Resolved struct {
	Name     string
	Version  string
	Hash     string // bundle hash (the signed identity)
	Tier     string // TierSigned | TierUnsigned
	Verified bool
	Content  string // the procedure text
}

// Audit is the per-skill record for the session log: which procedure informed this run, at what
// version, by what hash, in what tier. Nobody else's audit can answer "which procedure decided this."
type Audit struct {
	Name    string `json:"skill"`
	Version string `json:"version,omitempty"`
	Hash    string `json:"hash"`
	Tier    string `json:"tier"`
}

// Resolve verifies one skill's signature against the operator's public key and assigns its tier. A
// nil/short key, an absent signature, a wrong key, or a tampered bundle (hash mismatch) all fail
// closed to TierUnsigned — the skill is still usable, just as untrusted reference.
func Resolve(operatorPub ed25519.PublicKey, sk provider.Skill) Resolved {
	verified := egress.VerifySkillSig(operatorPub, sk.BundleHash(), sk.Signature())
	tier := TierUnsigned
	if verified {
		tier = TierSigned
	}
	return Resolved{
		Name: sk.Name(), Version: sk.Version(), Hash: sk.BundleHash(),
		Tier: tier, Verified: verified, Content: sk.Text(),
	}
}

// Partition splits resolved skills into a System addendum (verified procedures, trusted operator
// instruction appended to the system prompt) and Input docs (unverified skills, untrusted reference),
// and returns the audit trail. This is the placement the doctrine turns on: verified -> System,
// everything else -> Input.
func Partition(resolved []Resolved) (systemAddendum string, inputDocs []bind.Doc, audit []Audit) {
	var sys []string
	for _, r := range resolved {
		audit = append(audit, Audit{Name: r.Name, Version: r.Version, Hash: r.Hash, Tier: r.Tier})
		if r.Verified {
			sys = append(sys, "\n\n<skill name=\""+r.Name+"\" trusted=\"operator-signed\">\n"+r.Content+"\n</skill>")
		} else {
			inputDocs = append(inputDocs, bind.Doc{Source: "skill:" + r.Name + " (UNSIGNED — untrusted)", Text: r.Content})
		}
	}
	for _, s := range sys {
		systemAddendum += s
	}
	return systemAddendum, inputDocs, audit
}
