package record

import (
	"math"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

func baseEvent() ReleaseEvent {
	return ReleaseEvent{
		SubjectClass:    trust.Untrusted,
		SubjectOrigin:   "retriever.runbooks",
		CollectedField:  "classify.output.action",
		TargetClass:     trust.Authoritative,
		TargetField:     "act.args.action",
		AuthorizingRule: "actions.approved",
		Actor:           "policy:remediation",
		Ordering:        7,
		RecipeHash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
}

func TestReleaseEvent(t *testing.T) {
	e := baseEvent()

	h1, err := e.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h2, _ := e.Hash(); h1 != h2 {
		t.Errorf("stability: repeated hash differs")
	}
	if !isHex64(h1) {
		t.Errorf("format: %q not 64 hex", h1)
	}

	// legible canonical form pins the shape (class NAMES, int64 ordering, snake_case keys)
	want, err := CanonicalHash(map[string]any{
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
	if err != nil {
		t.Fatal(err)
	}
	if h1 != want {
		t.Errorf("canonical shape: %q != %q", h1, want)
	}

	// tamper-evidence: changing any one of the nine fields changes the hash
	mutators := []struct {
		name string
		mut  func(*ReleaseEvent)
	}{
		{"SubjectClass", func(e *ReleaseEvent) { e.SubjectClass = trust.Caller }},
		{"SubjectOrigin", func(e *ReleaseEvent) { e.SubjectOrigin = "retriever.web" }},
		{"CollectedField", func(e *ReleaseEvent) { e.CollectedField = "classify.output.other" }},
		{"TargetClass", func(e *ReleaseEvent) { e.TargetClass = trust.Caller }},
		{"TargetField", func(e *ReleaseEvent) { e.TargetField = "act.args.other" }},
		{"AuthorizingRule", func(e *ReleaseEvent) { e.AuthorizingRule = "actions.other" }},
		{"Actor", func(e *ReleaseEvent) { e.Actor = "policy:other" }},
		{"Ordering", func(e *ReleaseEvent) { e.Ordering = 8 }},
		{"RecipeHash", func(e *ReleaseEvent) { e.RecipeHash = e.RecipeHash[:63] + "6" }}, // one-char edit
	}
	for _, m := range mutators {
		me := baseEvent()
		m.mut(&me)
		if mh, _ := me.Hash(); mh == h1 {
			t.Errorf("tamper-evidence: changing %s did not change the hash", m.name)
		}
	}

	// empty recipe hash: valid, stable, distinct (a missing binding is itself tamper-evident)
	ee := baseEvent()
	ee.RecipeHash = ""
	eh, err := ee.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if eh == h1 {
		t.Errorf("empty recipe_hash should differ from bound event")
	}
	if eh2, _ := ee.Hash(); eh2 != eh {
		t.Errorf("empty recipe_hash not stable")
	}

	// out-of-set class renders "unknown", hashes with nil error, stable, distinct
	oe := baseEvent()
	oe.SubjectClass = trust.TrustClass(99)
	oh, err := oe.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if oh == h1 {
		t.Errorf("out-of-set class should differ from in-set")
	}
	if oh2, _ := oe.Hash(); oh2 != oh {
		t.Errorf("out-of-set class not stable")
	}
}

func FuzzReleaseEvent(f *testing.F) {
	f.Add("o", "cf", "tf", "rule", "actor", "rh", int64(7), uint8(0), uint8(2))
	f.Add("", "", "", "", "", "", int64(0), uint8(1), uint8(3))
	f.Fuzz(func(t *testing.T, origin, cf, tf, rule, actor, recipeHash string, ordering int64, sc, tc uint8) {
		e := ReleaseEvent{
			SubjectClass:    trust.TrustClass(sc % 4),
			SubjectOrigin:   origin,
			CollectedField:  cf,
			TargetClass:     trust.TrustClass(tc % 4),
			TargetField:     tf,
			AuthorizingRule: rule,
			Actor:           actor,
			Ordering:        ordering,
			RecipeHash:      recipeHash,
		}
		h, err := e.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != 64 {
			t.Errorf("format: len=%d", len(h))
		}
		e2 := e
		if h2, _ := e2.Hash(); h2 != h {
			t.Errorf("STABILITY: identical event hashes differ")
		}
		if ordering != math.MaxInt64 {
			e3 := e
			e3.Ordering = ordering + 1
			if h3, _ := e3.Hash(); h3 == h {
				t.Errorf("TAMPER: ordering change did not change hash")
			}
		}
		e4 := e
		e4.RecipeHash = recipeHash + "x"
		if h4, _ := e4.Hash(); h4 == h {
			t.Errorf("TAMPER: recipe_hash change did not change hash")
		}
	})
}
