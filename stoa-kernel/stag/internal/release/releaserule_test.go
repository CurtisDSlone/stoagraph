package release_test

import (
	"strconv"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/release"
)

func TestReleaseRule(t *testing.T) {
	set := release.ReleaseRule{Kind: release.RuleSetMembership, Set: []string{"restart", "isolate", "notify"}}
	setCases := []struct {
		v    string
		want bool
	}{
		{"restart", true}, {"notify", true},
		{"reboot", false}, {"RESTART", false}, {"restart ", false}, {"res", false}, {"", false},
	}
	for _, c := range setCases {
		if got := set.Release(c.v); got != c.want {
			t.Errorf("set.Release(%q) = %v, want %v", c.v, got, c.want)
		}
	}
	if (release.ReleaseRule{Kind: release.RuleSetMembership}).Release("restart") {
		t.Errorf("empty set should release nothing")
	}

	signed := release.ReleaseRule{Kind: release.RuleSignedEquality, Signed: "v1.2.3"}
	signedCases := []struct {
		v    string
		want bool
	}{
		{"v1.2.3", true}, {"v1.2.4", false}, {"v1.2.3 ", false}, {"", false},
	}
	for _, c := range signedCases {
		if got := signed.Release(c.v); got != c.want {
			t.Errorf("signed.Release(%q) = %v, want %v", c.v, got, c.want)
		}
	}
	if (release.ReleaseRule{Kind: release.RuleSignedEquality}).Release("") {
		t.Errorf("empty signed should release nothing")
	}

	rng := release.ReleaseRule{Kind: release.RuleNumericRange, Min: 1, Max: 10}
	rngCases := []struct {
		v    string
		want bool
	}{
		{"1", true}, {"5", true}, {"10", true},
		{"0", false}, {"11", false}, {"-3", false}, {"abc", false}, {"5x", false}, {" 5", false}, {"", false},
		// non-canonical spellings of in-range numbers must NOT release
		{"+5", false}, {"007", false}, {"05", false}, {"010", false},
	}
	for _, c := range rngCases {
		if got := rng.Release(c.v); got != c.want {
			t.Errorf("range.Release(%q) = %v, want %v", c.v, got, c.want)
		}
	}
	if (release.ReleaseRule{Kind: release.RuleNumericRange, Min: 10, Max: 1}).Release("5") {
		t.Errorf("empty range should release nothing")
	}

	if release.RuleSetMembership.String() != "set_membership" || release.RuleSignedEquality.String() != "signed_equality" ||
		release.RuleNumericRange.String() != "numeric_range" || release.RuleKind(99).String() != "unknown" {
		t.Errorf("RuleKind.String mismatch")
	}

	// ParseRuleKind is the exact inverse of String over the three kinds; fail closed off it.
	for _, k := range []release.RuleKind{release.RuleSetMembership, release.RuleSignedEquality, release.RuleNumericRange} {
		if got, err := release.ParseRuleKind(k.String()); err != nil || got != k {
			t.Errorf("round-trip: ParseRuleKind(%q) = %v, %v; want %v, nil", k.String(), got, err, k)
		}
	}
	for _, s := range []string{"set", "signed-equality", "numeric-range", "unknown", "", " set_membership ", "SET_MEMBERSHIP"} {
		if got, err := release.ParseRuleKind(s); err == nil || got != release.RuleKind(-1) {
			t.Errorf("fail-closed: ParseRuleKind(%q) = %v, %v; want -1, error", s, got, err)
		}
	}

	if (release.ReleaseRule{Kind: release.RuleKind(99), Set: []string{"restart"}}).Release("restart") {
		t.Errorf("unknown kind should release nothing")
	}
	if (release.ReleaseRule{Kind: release.RuleKind(-1), Set: []string{"restart"}}).Release("restart") {
		t.Errorf("sentinel kind should release nothing")
	}
}

func FuzzReleaseRule(f *testing.F) {
	for _, s := range []string{"restart", "isolate", "notify", "restart ", "RESTART", "5", "+5", "007", "10", "010", "11", "0", "", "-3", "v1.2.3", "set_membership", "signed_equality", "numeric_range", "set"} {
		f.Add(s)
	}

	members := []string{"restart", "isolate", "notify"}
	// canonical in-range strings for [1,10], enumerated independently of Release's parser.
	rangeMembers := map[string]bool{}
	for n := int64(1); n <= 10; n++ {
		rangeMembers[strconv.FormatInt(n, 10)] = true
	}
	const signedRef = "v1.2.3"

	f.Fuzz(func(t *testing.T, value string) {
		// set: release iff value is an exact member.
		isMember := false
		for _, m := range members {
			if value == m {
				isMember = true
			}
		}
		if got := (release.ReleaseRule{Kind: release.RuleSetMembership, Set: members}).Release(value); got != isMember {
			t.Errorf("LAUNDERING set: Release(%q) = %v, want %v", value, got, isMember)
		}

		// range: release iff value is a canonical in-range string (independent oracle).
		if got := (release.ReleaseRule{Kind: release.RuleNumericRange, Min: 1, Max: 10}).Release(value); got != rangeMembers[value] {
			t.Errorf("LAUNDERING range: Release(%q) = %v, want %v", value, got, rangeMembers[value])
		}

		// signed: release iff exact match to the non-empty reference.
		if got := (release.ReleaseRule{Kind: release.RuleSignedEquality, Signed: signedRef}).Release(value); got != (value == signedRef) {
			t.Errorf("LAUNDERING signed: Release(%q) = %v, want %v", value, got, value == signedRef)
		}

		// string/parse inverse: parse only ever accepts a canonical spelling and round-trips it exactly.
		if k, err := release.ParseRuleKind(value); err == nil {
			if k.String() != value {
				t.Errorf("PARSE non-inverse: ParseRuleKind(%q) accepted but String()=%q", value, k.String())
			}
		} else if k != release.RuleKind(-1) {
			t.Errorf("PARSE fail-open: ParseRuleKind(%q) errored but returned %v, want sentinel -1", value, k)
		}
	})
}
