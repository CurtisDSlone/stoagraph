package dispatch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/localtools"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
)

// LocalTransport carries an authorized call to the declared local-tool surface — the SAME
// execution path an ordinary gated call takes, so an authorized sequence gets the argv
// discipline (per-element substitution, no shell) rather than a second, weaker one.

func toolsYAML(t *testing.T, dir string) localtools.Config {
	t.Helper()
	src := `
root: ` + dir + `
timeout: 10s
env_allow: []
tools:
  - name: echo_it
    description: echo a value
    command: [echo, "{value}"]
    args:
      value: {description: the value to echo}
  - name: fail_it
    description: always fails
    command: [false]
    args: {}
`
	p := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := localtools.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLocalTransportRunsTheDeclaredTool(t *testing.T) {
	cfg := toolsYAML(t, t.TempDir())
	tr := NewLocalTransport(cfg)
	out, err := tr.Call(context.Background(), proxy.ToolCall{Tool: "echo_it", Args: map[string]string{"value": "hello"}})
	if err != nil {
		t.Fatalf("declared tool must run: %v", err)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("output not returned: %q", out)
	}
}

// An undeclared tool is an error, never a run. The transport may only carry calls to the
// surface the operator authored.
func TestLocalTransportRefusesUndeclaredTool(t *testing.T) {
	cfg := toolsYAML(t, t.TempDir())
	tr := NewLocalTransport(cfg)
	if _, err := tr.Call(context.Background(), proxy.ToolCall{Tool: "not_a_tool"}); err == nil {
		t.Error("an undeclared tool must not run")
	}
}

// A non-zero exit is a transport ERROR, so the sequence halts on it. A tool that failed is
// not a step that succeeded, and the executor must not carry on as though it were.
func TestLocalTransportNonZeroExitIsAnError(t *testing.T) {
	cfg := toolsYAML(t, t.TempDir())
	tr := NewLocalTransport(cfg)
	if _, err := tr.Call(context.Background(), proxy.ToolCall{Tool: "fail_it", Args: map[string]string{}}); err == nil {
		t.Error("a failing tool must surface as a transport error so the sequence halts")
	}
}

// The injection defence is inherited, not reimplemented: a value with shell metacharacters
// is ONE argument, exactly as localtools guarantees.
func TestLocalTransportInheritsArgvDiscipline(t *testing.T) {
	cfg := toolsYAML(t, t.TempDir())
	tr := NewLocalTransport(cfg)
	payload := "x; rm -rf /"
	out, err := tr.Call(context.Background(), proxy.ToolCall{Tool: "echo_it", Args: map[string]string{"value": payload}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, payload) {
		t.Errorf("the payload must survive as ONE literal argument: %q", out)
	}
}
