package record

// file-kw: decision record audit unit tool verdict forwarded value recipe fault releases

// DecisionRecord is ONE gate decision — the unit of the audit chain.
//
// The chain records EVERY decision, not only the permitted ones. A deny is evidence the control did its
// job: an auditor asking "did anything try to reach that repo?" needs the blocked attempts as much as
// the allowed ones, and a log of only the allows cannot answer the question it exists to answer.
//
// The load-bearing invariant is the other half. Events are RELEASES — moments an untrusted value
// actually crossed into an authoritative sink — and they are carried ONLY when the call was Forwarded.
// A denied call releases nothing, even if some of its sinks individually cleared (a multi-arg recipe
// evaluates every sink; one can pass while a sibling fails and denies the whole call). Recording those
// would assert a crossing that never happened. The record states what HAPPENED, never what merely
// evaluated.
type DecisionRecord struct {
	Tool       string
	Verdict    string // allow | deny | escalate
	Forwarded  bool   // did the call actually reach the tool?
	Value      string // the bound gated argument(s): "hello", or "owner=curtis repo=stoagraph"
	Recipe     string
	RecipeHash string
	Fault      string         // why it was not allowed ("" when allowed)
	Events     []ReleaseEvent // crossings actually released; ALWAYS empty unless Forwarded
}

// kw: decision canonical hash tamper-evident leaf payload
func (d DecisionRecord) Hash() (string, error) { return CanonicalHash(d) }
