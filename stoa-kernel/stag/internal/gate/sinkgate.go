package gate

// file-kw: sink gate abac decision authoritative benign release fail-safe mediation

import (
	"fmt"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/trust"
)

// kw: sink sensitivity authoritative benign
type SinkSensitivity int

// kw: sink sensitivity constants benign authoritative
const (
	SinkBenign SinkSensitivity = iota
	SinkAuthoritative
)

// kw: sink sensitivity string
func (s SinkSensitivity) String() string {
	switch s {
	case SinkBenign:
		return "benign"
	case SinkAuthoritative:
		return "authoritative"
	default:
		return "unknown"
	}
}

// kw: parse sink sensitivity
func ParseSinkSensitivity(s string) (SinkSensitivity, error) {
	switch s {
	case "benign":
		return SinkBenign, nil
	case "authoritative":
		return SinkAuthoritative, nil
	default:
		return SinkSensitivity(-1), fmt.Errorf("invalid sink sensitivity: %q", s) // fail closed
	}
}

// kw: gate sink abac decision verdict
func GateSink(subject trust.TrustClass, sink SinkSensitivity, released bool) Verdict {
	switch sink {
	case SinkBenign:
		return Allow // not release-gated
	case SinkAuthoritative:
		if released {
			return Allow // declassifier cleared this crossing
		}
		if subject == trust.Authoritative {
			return Allow
		}
		return Deny // Caller, Untrusted, severed: deny unless released (inv 8)
	default:
		return Deny // complete mediation (inv 10)
	}
}
