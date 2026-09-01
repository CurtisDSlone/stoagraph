package record

// file-kw: release event trust crossing record hashed attestation four dimensions tamper-evident

import "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"

// kw: release event trust crossing record
type ReleaseEvent struct {
	SubjectClass    trust.TrustClass
	SubjectOrigin   string
	CollectedField  string
	TargetClass     trust.TrustClass
	TargetField     string
	AuthorizingRule string
	Actor           string
	Ordering        int64
	RecipeHash      string
}

// kw: release event canonical hash tamper-evident
func (e ReleaseEvent) Hash() (string, error) {
	// legible canonical form: classes by name, int64 ordering exact (U5 caveat)
	return CanonicalHash(map[string]any{
		"subject_class":    e.SubjectClass.String(),
		"subject_origin":   e.SubjectOrigin,
		"collected_field":  e.CollectedField,
		"target_class":     e.TargetClass.String(),
		"target_field":     e.TargetField,
		"authorizing_rule": e.AuthorizingRule,
		"actor":            e.Actor,
		"ordering":         e.Ordering,
		"recipe_hash":      e.RecipeHash,
	})
}
