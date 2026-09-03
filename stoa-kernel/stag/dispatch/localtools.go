package dispatch

// file-kw: local transport declared tools argv discipline carry authorized call exit-code halt

import (
	"context"
	"fmt"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/localtools"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// LocalTransport carries an authorized call to the operator-declared local-tool surface.
//
// It adds NO execution path of its own: it looks the tool up in the same declared config an
// ordinary gated call uses and hands the arguments to localtools.Run, which substitutes
// per-argv-element and never invokes a shell. So an authorized sequence inherits the
// injection defence rather than reimplementing a weaker copy of it.
// kw: local transport declared surface run inherit argv discipline
type LocalTransport struct {
	cfg localtools.Config
}

// kw: new local transport from declared config
func NewLocalTransport(cfg localtools.Config) *LocalTransport { return &LocalTransport{cfg: cfg} }

// Call runs one authorized call. An undeclared tool, a failed start, and a NON-ZERO EXIT are
// all errors: the executor halts the sequence on any of them. A tool that failed is not a
// step that succeeded, and a sequence that carried on past a failure would be reporting a
// result it does not have.
// kw: call run declared tool exit code error halt truncated timeout
func (l *LocalTransport) Call(ctx context.Context, c proxy.ToolCall) (string, error) {
	tool, ok := l.cfg.Find(c.Tool)
	if !ok {
		return "", fmt.Errorf("no declared tool %q", c.Tool)
	}
	res, err := l.cfg.Run(ctx, tool, c.Args)
	if err != nil {
		return "", err
	}
	if res.TimedOut {
		return res.Output, fmt.Errorf("tool %q timed out", c.Tool)
	}
	if res.ExitCode != 0 {
		return res.Output, fmt.Errorf("tool %q exited %d", c.Tool, res.ExitCode)
	}
	return res.Output, nil
}
