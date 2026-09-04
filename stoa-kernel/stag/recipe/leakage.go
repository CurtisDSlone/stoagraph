package recipe

// file-kw: leakage choice-channel covert bound forwarded-tuples logsumexp foreach-geom per-call existence session

// Leakage computes the CHOICE-CHANNEL bound for a recipe: how much a fully prompt-injected model could
// exfiltrate to an external observer through the *choices* it makes among what the gate ALLOWS. Even a
// closed-set gate lets the model pick WHICH allowed value crosses; the gate does not remove that
// channel, it makes it BOUNDED and STATICALLY COMPUTABLE — derived from the policy alone, with no model
// in the computation. Runtime leakage-budget mediators exist in the literature; they accumulate over a
// trajectory and typically put a model in the measurement path. This bound trades that finer semantic
// tradeoff for a ceiling that is a pure function of what was authored.
//
// The model was DERIVED AND ADVERSARIALLY VERIFIED (2026-07-15): five independent lenses attacked a
// naive Σ log2(K_i) bound and an adjudicator corrected it. The corrections that matter:
//   - A recipe governs ONE tool call. F(R) = the number of distinct FORWARDED value-tuples of that
//     call = product of each gated arg's admitted-value count along a path, SUMMED over branches
//     (the attacker may take any), with a foreach body contributing a geometric series over its
//     iteration cap. This is log2-domain: sink=+log2(c), branch=logsumexp, foreach=logGeom.
//   - EXISTENCE is per-CALL, not per-sink: the model can force the whole call to deny (propose a
//     failing value), and "not forwarded" is one observable outcome. So a call carries F(R)+1
//     outcomes -> CallBits = log2(F(R)+1). A signed_equality-only call therefore leaks 1 bit, not 0.
//   - A benign/ruleless sink of a slot a GATE already constrained is NOT free text (the value was
//     bounded upstream); it is free text -> UNBOUNDED only if its slot was never constrained.
//   - A free-text `passthrough` argument VOIDS the bound (unbounded). The leakage bound exists exactly
//     when every output-reaching argument is closed-set — the same theorem as the coverage contract.
//
// Session-level composition (N such calls across M advertised recipes) is SessionBound(); ordering is
// SUBSUMED by the length-<=N sequence count (do NOT add log2(N!)).
//
// STATED PRECONDITIONS for the number to be a real ceiling (see the design doc): canonical-only
// release (enforced), an order-only / log-private / semantic-value observer, and — not yet enforced —
// a gate-side per-session crossing cap N and an advertise-time refusal of unbounded recipes. The
// number is a per-session RATE, not a lifetime guarantee.

import (
	"fmt"
	"math"
	"strings"

	stag "github.com/CurtisDSlone/stoagraph/stoa-kernel/stag"
)

// metaApprovalToken mirrors proxy.MetaApprovalToken (recipe cannot import proxy — cycle). It is the
// gate-only approval slot, STRIPPED before forwarding, so it is never a free-text egress.
const metaApprovalToken = "approval_token"

// ConstrainedSlots returns the recipe slots a value-bounding rule constrains: the `In` of every gate and
// sink that carries a rule. A route that forwards an argument whose slot is NOT in this set forwards it
// as free-text — the recipe never restricts its value — even if the argument is "covered" by being listed
// in the route's gateArg. Boundedness is therefore a property of (recipe, gateArg), not the recipe alone.
func ConstrainedSlots(r stag.Recipe) map[string]bool {
	c := map[string]bool{}
	for _, st := range r.Steps {
		if (st.Kind == stag.NodeGate || st.Kind == stag.NodeSink) && st.Rule != nil {
			c[st.In] = true
		}
	}
	return c
}

// RouteFreeText returns the gate-arg slots this route forwards that the recipe never constrains with a
// bounding rule — a silent free-text channel that the recipe-only Leakage check cannot see. This is the
// route-level companion to the passthrough check: declaring `passthrough:[x]` is refused under strict
// mode, and so must be the identical free-text channel expressed by listing x in gateArg without gating
// it. The gate-only approval token is stripped before forwarding, so it is skipped.
//
// NOTE (documented residual): a slot constrained only on SOME branches (e.g. gated in a case but forwarded
// unconstrained on a catch-all default) is treated as constrained here. Closing that requires per-path
// analysis; the common and reported hole — a gateArg slot the recipe never constrains at all — is caught.
func RouteFreeText(r stag.Recipe, gateArg string) []string {
	// Single-arg gating binds the one value POSITIONALLY to the recipe's flow, so the gate-arg name need
	// not match a recipe slot name — and an unconstrained single flow is already an ungated sink, which
	// Leakage(recipe) reports as Unbounded. The name-based check is only meaningful for MULTI-arg gating,
	// where EvalArgs binds by NAME and a gate-arg slot with no matching constrained recipe slot is
	// silently ignored by evaluation yet still forwarded — the free-text hole this closes.
	if !strings.Contains(gateArg, ",") {
		return nil
	}
	constrained := ConstrainedSlots(r)
	var out []string
	for _, path := range strings.Split(gateArg, ",") {
		path = strings.TrimSpace(path)
		if path == "" || path == metaApprovalToken {
			continue
		}
		if slot := gateArgSlot(path); !constrained[slot] {
			out = append(out, slot)
		}
	}
	return out
}

// gateArgSlot is the recipe slot a gate-arg path binds: its last segment, minus a trailing []
// (`files[].path` -> `path`), mirroring proxy.slotName.
func gateArgSlot(path string) string {
	seg := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		seg = path[i+1:]
	}
	return strings.TrimSuffix(seg, "[]")
}

// LeakageReport is the choice-channel bound for ONE call of a recipe.
type LeakageReport struct {
	// CallBits = log2(F(R)+1): the max bits one forwarded call of this recipe can carry — the value
	// tuple choice plus the fire/suppress existence bit. Meaningful only when !Unbounded.
	CallBits float64
	// ForwardedTuples = log2(F(R)): log2 of the number of distinct forwarded value-tuples (no existence).
	ForwardedTuples float64
	Unbounded       bool
	UnboundedReason string
	Note            string
}

// maxVisits guards the constraint-tracking DFS against a pathological branch explosion (real recipes
// are tiny; this only trips on an adversarially-wide graph, where we fail closed to unbounded).
const maxVisits = 200000

// foreachCap mirrors the kernel's unexported inv-13 bound (stag.foreachCap = 64): the fixed max number
// of elements a foreach may iterate. The geometric series over a loop is summed to this cap.
const foreachCap = 64

// Leakage analyzes one compiled recipe. Pure function of the recipe graph + its gated set sizes.
func Leakage(r stag.Recipe) LeakageReport {
	if len(r.PassThrough) > 0 {
		return LeakageReport{Unbounded: true, UnboundedReason: fmt.Sprintf("free-text passthrough argument(s): %v", r.PassThrough)}
	}
	idx := map[string]int{}
	for i, st := range r.Steps {
		idx[st.Id] = i
	}
	n := len(r.Steps)
	if n == 0 {
		return LeakageReport{}
	}

	visits := 0
	var ub string // set to the reason on the first unbounded crossing encountered

	// walk returns log2(F) for forwarded paths from step i, given the current per-slot constraints
	// (cons[slot] = admitted-value count established by a gate; absent = unconstrained). cons is copied
	// on any state change so sibling branches do not see each other's constraints.
	var walk func(i int, cons map[string]int64) float64
	walk = func(i int, cons map[string]int64) float64 {
		if ub != "" || i < 0 {
			return 0 // i<0: fell off the end of the recipe = the call completes (one empty tuple)
		}
		visits++
		if visits > maxVisits {
			ub = "recipe graph too large to bound statically (fail closed)"
			return 0
		}
		st := r.Steps[i]
		switch st.Kind {
		case stag.NodeExit:
			return 0 // one empty tuple = 2^0

		case stag.NodePropose:
			c2 := cloneDrop(cons, st.Out) // a freshly proposed slot is unconstrained
			return walk(next(i, st, idx, n), c2)

		case stag.NodeGate:
			// pass path only (fail = deny/escalate, not forwarded). The gate constrains its slot.
			c2 := clone(cons)
			if st.Rule != nil {
				c2[st.In] = ruleChoices(st.Rule)
			}
			return walk(next(i, st, idx, n), c2)

		case stag.NodeSink:
			choices, isUB, reason := sinkChoices(st, cons)
			if isUB {
				if ub == "" {
					ub = reason
				}
				return 0
			}
			if choices < 0 { // defensive: an overflowed/garbage count must never score as 0 bits
				if ub == "" {
					ub = fmt.Sprintf("sink %q has an uncomputable choice count (fail closed)", st.Id)
				}
				return 0
			}
			add := 0.0
			if choices > 1 {
				add = math.Log2(float64(choices))
			}
			return add + walk(next(i, st, idx, n), cons)

		case stag.NodeBranch:
			// the attacker may take ANY case -> the observable transcript count is the SUM over cases.
			var terms []float64
			for _, c := range st.Cases {
				j, ok := idx[c.Goto]
				if !ok {
					continue
				}
				c2 := clone(cons)
				if c.Rule != nil {
					c2[st.In] = ruleChoices(c.Rule) // on this case's path, `in` matched this rule
				}
				terms = append(terms, walk(j, c2))
			}
			if j, ok := idx[st.Default]; ok {
				terms = append(terms, walk(j, clone(cons)))
			}
			return log2SumExp(terms)

		case stag.NodeForeach:
			// the body runs 0..foreachCap times over an attacker-chosen list; the forwarded-tuple count
			// per loop is a geometric series in the body's per-iteration count.
			bodyF := walk(next(i, st, idx, n), cloneSet(cons, st.As, -1))
			return logGeom(bodyF, foreachCap)

		default:
			return walk(next(i, st, idx, n), cons)
		}
	}

	logF := walk(0, map[string]int64{})
	if ub != "" {
		return LeakageReport{Unbounded: true, UnboundedReason: ub}
	}
	// CallBits = log2(F+1): F forwarded tuples + 1 "suppressed/denied" (fire-vs-suppress), per CALL.
	callBits := log2SumExp([]float64{logF, 0}) // log2(2^logF + 2^0) = log2(F+1)
	return LeakageReport{
		CallBits:        callBits,
		ForwardedTuples: logF,
		Note: "per-CALL bound of this recipe. A SESSION of N calls across M advertised recipes is " +
			"SessionBound(): L <= N*log2(1 + Σ_m(F(R_m)+Esc_m)). Ordering is subsumed (no +log2(N!)).",
	}
}

// SessionBound composes the per-session ceiling over the recipes advertised to one agent session and a
// gate-enforced per-session crossing cap n: L_session = log2(Σ_{t=0}^{n} Ψ^t) <= n*log2(1+Ψ), where
// Ψ = Σ_m (F(R_m) + Esc_m) is the per-turn observable alphabet. Unbounded if any advertised recipe is.
func SessionBound(recipes []stag.Recipe, n int) (bits float64, unbounded bool, reason string) {
	psiTerms := []float64{}
	for i, r := range recipes {
		lr := Leakage(r)
		if lr.Unbounded {
			return 0, true, fmt.Sprintf("advertised recipe #%d: %s", i, lr.UnboundedReason)
		}
		psiTerms = append(psiTerms, lr.ForwardedTuples) // log2 F(R_m)
		if escalatable(r) {
			psiTerms = append(psiTerms, 0) // + one escalate symbol
		}
	}
	logPsi := log2SumExp(psiTerms)
	return logGeom(logPsi, n), false, ""
}

// sinkChoices returns the admitted-value count for a sink's release: its own rule if it has one, else
// the upstream gate constraint on its slot, else free text (unbounded).
func sinkChoices(st stag.Step, cons map[string]int64) (int64, bool, string) {
	if st.Rule != nil {
		return ruleChoices(st.Rule), false, ""
	}
	if c, ok := cons[st.In]; ok && c >= 0 {
		return c, false, ""
	}
	if st.Sensitivity == stag.SinkBenign {
		return 0, true, fmt.Sprintf("benign sink %q forwards an unconstrained (free-text) value", st.Id)
	}
	return 0, true, fmt.Sprintf("sink %q releases an unconstrained value", st.Id)
}

func ruleChoices(rule *stag.ReleaseRule) int64 {
	switch rule.Kind {
	case stag.RuleSetMembership:
		return int64(len(rule.Set))
	case stag.RuleNumericRange:
		if rule.Max < rule.Min {
			return 0
		}
		// Max-Min+1 OVERFLOWS int64 for a wide range (e.g. [0, MaxInt64] wraps to MinInt64, a negative
		// count that would score as 0 bits and hide a ~63-bit channel). Saturate instead: a range that
		// spans (nearly) the whole int64 leaks ~63 bits, so report a large-but-finite count.
		d := rule.Max - rule.Min
		if d < 0 || d == math.MaxInt64 {
			return math.MaxInt64
		}
		return d + 1
	case stag.RuleSignedEquality:
		return 1
	default:
		return 1
	}
}

func escalatable(r stag.Recipe) bool {
	for _, st := range r.Steps {
		if st.Kind == stag.NodeGate && st.Escalate {
			return true
		}
	}
	return false
}

// next is the forward successor of a non-branch step: its explicit goto, else fall-through, else -1
// (fell off the end — the call completes).
func next(i int, st stag.Step, idx map[string]int, n int) int {
	if st.Goto != "" {
		if j, ok := idx[st.Goto]; ok {
			return j
		}
	}
	if i+1 < n {
		return i + 1
	}
	return -1
}

func clone(m map[string]int64) map[string]int64 {
	c := make(map[string]int64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
func cloneDrop(m map[string]int64, k string) map[string]int64 { c := clone(m); delete(c, k); return c }
func cloneSet(m map[string]int64, k string, v int64) map[string]int64 {
	c := clone(m)
	c[k] = v
	return c
}

// log2SumExp = log2(Σ 2^x_i), numerically stable. Empty -> -Inf (zero tuples).
func log2SumExp(xs []float64) float64 {
	if len(xs) == 0 {
		return math.Inf(-1)
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	if math.IsInf(m, -1) {
		return m
	}
	s := 0.0
	for _, x := range xs {
		s += math.Exp2(x - m)
	}
	return m + math.Log2(s)
}

// logGeom = log2(Σ_{t=0}^{L} (2^lf)^t): the forwarded-tuple count of a loop whose body carries lf bits
// per iteration, over 0..L iterations. lf==0 (a single-value body) -> log2(L+1): the length channel.
func logGeom(lf float64, L int) float64 {
	if lf == 0 {
		return math.Log2(float64(L + 1))
	}
	xs := make([]float64, 0, L+1)
	for t := 0; t <= L; t++ {
		xs = append(xs, lf*float64(t))
	}
	return log2SumExp(xs)
}
