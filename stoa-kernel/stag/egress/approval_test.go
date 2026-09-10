package egress_test

import (
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
)

func TestSignApprovalRoundTrip(t *testing.T) {
	pub, priv, err := egress.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fp := "scale_deployment\x1fnamespace=prod\x1freplicas=3"
	tok := egress.SignApproval(priv, fp)

	if tok == "" {
		t.Fatal("token must not be empty")
	}
	if !egress.VerifyApproval(pub, fp, tok) {
		t.Error("a token must verify against its own fingerprint + key")
	}
	// deterministic (RFC 8032): the same action signs to the same token.
	if egress.SignApproval(priv, fp) != tok {
		t.Error("signing must be deterministic")
	}
	// a token for one action must NOT authorize a different action.
	if egress.VerifyApproval(pub, "scale_deployment\x1fnamespace=prod\x1freplicas=99", tok) {
		t.Error("token must not verify for a different fingerprint")
	}
	// a different key must not verify.
	otherPub, _, _ := egress.GenerateKey()
	if egress.VerifyApproval(otherPub, fp, tok) {
		t.Error("token must not verify under a different key")
	}
	// garbage / tampered token fails closed.
	if egress.VerifyApproval(pub, fp, "not-base64-!!") || egress.VerifyApproval(pub, fp, "") {
		t.Error("malformed token must fail closed")
	}
}
