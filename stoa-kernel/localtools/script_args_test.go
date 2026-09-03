package localtools

// kw-test: script args are NAMED flags, never positional — a rename must not silently transpose values

import (
	"context"
	"strings"
	"testing"
)

// A script's declared args arrive as `--name value`, so the script reads them BY NAME.
//
// This replaced positional passing, which was ordered alphabetically because Args is a map (Go
// randomizes map iteration; a YAML mapping has no order). That made the real contract "alphabetical
// by argument name" — invisible at the call site. Declaring {path, find, replace} handed the script
// find, path, replace, and a script written to the YAML's own order read one value as another with
// no error anywhere. This test pins the fix.
func TestScriptArgsArePassedAsNamedFlags(t *testing.T) {
	dir := t.TempDir()
	// Echoes each flag/value pair on its own line, so a transposition is visible in the output.
	// Echoes argv one element per line. Positional passing shows bare values; named flags show the
	// --name lines the assertions look for. Never loops on argv, so a wrong contract fails fast.
	script := write(t, dir, "echo_args.sh", "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\n")

	tool := Tool{
		Name:   "edit",
		Script: script,
		// Declared in an order that is NOT alphabetical: under the old positional contract the
		// script would have received find, path, replace and mis-read every one.
		Args: map[string]Arg{
			"path":    {Description: "the file"},
			"find":    {Description: "text to find"},
			"replace": {Description: "text to write"},
		},
	}
	cfg := Config{Root: dir, Tools: []Tool{tool}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	res, err := cfg.Run(context.Background(), tool, map[string]string{
		"path": "README.md", "find": "alpha", "replace": "beta",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Each flag immediately precedes its own value, so a transposition cannot pass.
	for _, want := range []string{"--path\nREADME.md", "--find\nalpha", "--replace\nbeta"} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("script did not receive %q as a named flag; argv was:\n%s",
				strings.SplitN(want, "\n", 2)[0], res.Output)
		}
	}
}

// The argv must be deterministic: the audit replays decisions, so the same recipe and the same call
// have to produce the same invocation at the tool boundary too.
func TestScriptArgvIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "echo_args.sh", "#!/bin/sh\necho \"$@\"\n")
	tool := Tool{Name: "t", Script: script,
		Args: map[string]Arg{"zeta": {}, "alpha": {}, "mid": {}}}
	cfg := Config{Root: dir, Tools: []Tool{tool}}
	args := map[string]string{"zeta": "z", "alpha": "a", "mid": "m"}

	first, err := cfg.Run(context.Background(), tool, args)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for i := 0; i < 8; i++ { // map iteration is randomized per run; 8 draws would expose it
		again, err := cfg.Run(context.Background(), tool, args)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if again.Output != first.Output {
			t.Fatalf("argv is not deterministic:\n  %q\n  %q", first.Output, again.Output)
		}
	}
}
