package skill_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/skill"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

// bundleDir writes a skill bundle (procedure files + optional sidecars) and returns its path.
func bundleDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// sign a bundle by loading it (to get the canonical hash), signing that hash, and writing SKILL.sig.
func signBundle(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	sk, err := provider.NewSkill("triage", dir)
	if err != nil {
		t.Fatal(err)
	}
	sig := egress.SignSkill(priv, sk.BundleHash())
	if err := os.WriteFile(filepath.Join(dir, "SKILL.sig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A correctly-signed skill, verified against the operator key, earns the SIGNED tier -> System slot.
func TestSignedSkillReachesSystem(t *testing.T) {
	pub, priv, _ := egress.GenerateKey()
	dir := bundleDir(t, map[string]string{"proc.md": "1. cordon node\n2. drain\n"})
	signBundle(t, dir, priv)

	sk, err := provider.NewSkill("triage", dir)
	if err != nil {
		t.Fatal(err)
	}
	r := skill.Resolve(pub, sk)
	if !r.Verified || r.Tier != skill.TierSigned {
		t.Fatalf("a correctly-signed skill must verify: %+v", r)
	}
	sys, docs, audit := skill.Partition([]skill.Resolved{r})
	if !strings.Contains(sys, "cordon node") || !strings.Contains(sys, `trusted="operator-signed"`) {
		t.Fatalf("a signed skill must go to the System addendum: %q", sys)
	}
	if len(docs) != 0 {
		t.Fatal("a signed skill must NOT appear as an untrusted Input doc")
	}
	if len(audit) != 1 || audit[0].Tier != skill.TierSigned || audit[0].Hash != sk.BundleHash() {
		t.Fatalf("audit must record the signed tier + hash: %+v", audit)
	}
}

// An unsigned skill degrades to the Input slot (untrusted reference) — it can inform, never instruct.
func TestUnsignedSkillGoesToInput(t *testing.T) {
	pub, _, _ := egress.GenerateKey()
	dir := bundleDir(t, map[string]string{"proc.md": "do the thing"})
	sk, _ := provider.NewSkill("triage", dir) // no SKILL.sig
	r := skill.Resolve(pub, sk)
	if r.Verified || r.Tier != skill.TierUnsigned {
		t.Fatalf("an unsigned skill must not verify: %+v", r)
	}
	sys, docs, _ := skill.Partition([]skill.Resolved{r})
	if sys != "" {
		t.Fatal("an unsigned skill must not touch System")
	}
	if len(docs) != 1 || !strings.Contains(docs[0].Source, "UNSIGNED") {
		t.Fatalf("an unsigned skill must be an untrusted Input doc: %+v", docs)
	}
}

// A skill signed by the WRONG key fails against the operator key -> Input (fail closed).
func TestWrongKeyFailsToInput(t *testing.T) {
	operatorPub, _, _ := egress.GenerateKey()
	_, attackerPriv, _ := egress.GenerateKey() // a different (attacker) key signs the bundle
	dir := bundleDir(t, map[string]string{"proc.md": "malicious steps"})
	signBundle(t, dir, attackerPriv)

	sk, _ := provider.NewSkill("triage", dir)
	r := skill.Resolve(operatorPub, sk) // verified against the OPERATOR key, not the attacker's
	if r.Verified {
		t.Fatal("a skill signed by a non-operator key must NOT verify")
	}
}

// A TAMPERED bundle (content changed after signing) fails: the hash no longer matches what was
// signed. This is why the signature is over the content hash, not just present.
func TestTamperedBundleFails(t *testing.T) {
	pub, priv, _ := egress.GenerateKey()
	dir := bundleDir(t, map[string]string{"proc.md": "original safe steps"})
	signBundle(t, dir, priv)

	// tamper with the procedure AFTER signing
	if err := os.WriteFile(filepath.Join(dir, "proc.md"), []byte("attacker-injected steps"), 0o644); err != nil {
		t.Fatal(err)
	}
	sk, _ := provider.NewSkill("triage", dir)
	r := skill.Resolve(pub, sk)
	if r.Verified {
		t.Fatal("a bundle edited after signing must NOT verify (hash mismatch)")
	}
}

// The bundle hash is over the PROCEDURE only — adding a version sidecar does not change the identity
// the signature attests, so a signed skill stays signed when a version label is added.
func TestVersionSidecarDoesNotBreakSignature(t *testing.T) {
	pub, priv, _ := egress.GenerateKey()
	dir := bundleDir(t, map[string]string{"proc.md": "steps"})
	signBundle(t, dir, priv)
	// add a version sidecar AFTER signing
	if err := os.WriteFile(filepath.Join(dir, "SKILL.version"), []byte("v2.1"), 0o644); err != nil {
		t.Fatal(err)
	}
	sk, _ := provider.NewSkill("triage", dir)
	r := skill.Resolve(pub, sk)
	if !r.Verified {
		t.Fatal("a version sidecar must not change the signed identity (hash is over the procedure only)")
	}
	if r.Version != "v2.1" {
		t.Fatalf("version must be read from the sidecar: %q", r.Version)
	}
}
