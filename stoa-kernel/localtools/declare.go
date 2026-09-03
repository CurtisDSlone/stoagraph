// Package localtools is the LOCAL TOOL SURFACE: a declared set of commands, served to an agent as MCP
// tools, so the model gets real local capability without ever getting a shell.
//
// THE GUARDRAIL, and why this is a server rather than a command:
//
//	A tool's command is authored by the OPERATOR, never by the model. The model only fills declared
//	{placeholder} arguments, and argv is handed to the OS DIRECTLY — no shell, ever. So there is no
//	shell-injection surface: a value containing `; rm -rf /` is one argv element, not two commands.
//
// That is the same rule the gate enforces one layer up, and the two compose:
//
//	declaration (here)  constrains the SHAPE   — which commands exist, which arguments they take
//	recipe (the gate)   constrains the VALUES  — which values those arguments may hold
//
// Neither is sufficient alone. A declared `search_code(pattern)` still lets the model search for
// anything until a recipe bounds `pattern`; a recipe bounding `cmd` is worthless if the tool is
// `run_command(cmd)`, because no rule can meaningfully constrain an arbitrary shell string. The
// granularity of the tool is the granularity of the control.
package localtools

// file-kw: local tools declared command script placeholder argv no-shell guardrail mcp stdio

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// DefaultTimeout bounds a tool that hangs; a wedged tool must not wedge the agent.
const DefaultTimeout = 30 * time.Second

// Arg is one declared parameter. Its name is the {placeholder} the command interpolates.
// kw: arg declared parameter description required
type Arg struct {
	Description string `yaml:"description"`
	// Required defaults to TRUE: an undeclared-but-referenced argument would otherwise substitute to
	// empty and silently run a different command than the operator wrote.
	Optional bool `yaml:"optional"`
}

// Tool is one declared local capability.
// kw: tool declared name description command script args cwd timeout
type Tool struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Command     []string       `yaml:"command"` // argv, authored by the operator. Exec'd directly.
	Script      string         `yaml:"script"`  // or a script, dispatched by extension
	Args        map[string]Arg `yaml:"args"`
	Cwd         string         `yaml:"cwd"`     // relative to the config's Root
	Timeout     time.Duration  `yaml:"timeout"` // 0 => the config default
}

// Config is a declared toolset.
// kw: config root timeout tools env-allow
type Config struct {
	Root    string        `yaml:"root"`    // working directory for every tool (default: the config's dir)
	Timeout time.Duration `yaml:"timeout"` // default per-tool timeout
	// EnvAllow names environment variables a tool may see. Everything else is stripped: the tool server
	// may itself be a child of the gate, whose environment holds control-plane secrets, and a local tool
	// has no business reading them. Empty => a minimal PATH/HOME only.
	EnvAllow []string `yaml:"env_allow"`
	Tools    []Tool   `yaml:"tools"`
}

// placeholder matches {name} tokens in an argv element.
var placeholder = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// shells are argv[0] values that interpret their arguments as a program. A placeholder anywhere in a
// shell's script argument is `run_command` wearing a costume, and it is refused at load.
var shells = []string{"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}

// shellEvalFlags are the flags that make a shell take a program string on the command line.
var shellEvalFlags = []string{"-c", "/c", "/C", "-Command", "-command"}

// Load reads and validates a toolset. It FAILS CLOSED: any tool that violates a guardrail rejects the
// whole file, rather than being silently dropped and leaving the operator to wonder where it went.
// kw: load parse validate toolset fail-closed
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("localtools: %s: %w", path, err)
	}
	if c.Root == "" {
		c.Root = filepath.Dir(path)
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("localtools: %s: %w", path, err)
	}
	return c, nil
}

// Validate enforces the guardrails. These are STRUCTURAL: a toolset that could hand the model a shell
// does not load at all.
// kw: validate guardrail no-shell argv0-authored declared-args
func (c Config) Validate() error {
	if len(c.Tools) == 0 {
		return fmt.Errorf("no tools declared")
	}
	seen := map[string]bool{}
	for _, t := range c.Tools {
		if t.Name == "" {
			return fmt.Errorf("a tool has no name")
		}
		if seen[t.Name] {
			return fmt.Errorf("tool %q declared twice", t.Name)
		}
		seen[t.Name] = true
		if err := t.validate(); err != nil {
			return fmt.Errorf("tool %q: %w", t.Name, err)
		}
	}
	return nil
}

func (t Tool) validate() error {
	argv := t.argvTemplate()
	if len(argv) == 0 {
		return fmt.Errorf("declares neither `command` nor `script`")
	}

	// 1. THE COMMAND ITSELF IS AUTHORED. A placeholder in argv[0] would let the model choose the
	//    program to run — which is `run_command` by another name.
	if placeholder.MatchString(argv[0]) {
		return fmt.Errorf("argv[0] %q contains a placeholder: the command must be authored by you, "+
			"never chosen by the model", argv[0])
	}

	// 2. NO SHELL EVALUATION. `bash -c "{cmd}"` hands the model a shell through the back door: the
	//    value would be PARSED as a program, and no recipe can meaningfully constrain an arbitrary
	//    shell string. Refuse the shape, not just the obvious spelling.
	base := strings.ToLower(filepath.Base(argv[0]))
	if slices.Contains(shells, base) {
		for i := 1; i < len(argv); i++ {
			if !slices.Contains(shellEvalFlags, argv[i]) {
				continue
			}
			for _, rest := range argv[i+1:] {
				if placeholder.MatchString(rest) {
					return fmt.Errorf("`%s %s` with a placeholder in the script argument is a shell for the "+
						"model — the value would be parsed as a program. Declare the real command instead "+
						"(e.g. command: [rg, \"{pattern}\"]), or move the logic into a `script:` that takes "+
						"the value as an argument", base, argv[i])
				}
			}
		}
	}

	// 3. EVERY PLACEHOLDER IS DECLARED. An undeclared one substitutes to empty and silently runs a
	//    different command than the operator wrote.
	for _, tok := range argv {
		for _, m := range placeholder.FindAllStringSubmatch(tok, -1) {
			if _, ok := t.Args[m[1]]; !ok {
				return fmt.Errorf("uses {%s} but does not declare it under `args`", m[1])
			}
		}
	}

	// 4. EVERY DECLARED ARG IS USED. A declared-but-unused arg means the model can pass a value that
	//    goes nowhere — confusing at best, and a sign the declaration drifted from the command.
	joined := strings.Join(argv, "\x00")
	for name := range t.Args {
		if !strings.Contains(joined, "{"+name+"}") {
			return fmt.Errorf("declares arg %q but never uses {%s}", name, name)
		}
	}
	return nil
}

// argvTemplate is the tool's argv before substitution: an explicit command, or a script dispatched to
// an interpreter by extension.
func (t Tool) argvTemplate() []string {
	if len(t.Command) > 0 {
		return t.Command
	}
	if t.Script == "" {
		return nil
	}
	switch strings.ToLower(filepath.Ext(t.Script)) {
	case ".sh":
		return append([]string{"sh", t.Script}, t.argNamesAsFlags()...)
	case ".py":
		return append([]string{"python3", t.Script}, t.argNamesAsFlags()...)
	default:
		return append([]string{t.Script}, t.argNamesAsFlags()...) // shebang / executable bit
	}
}

// argNamesAsFlags passes a script's declared args as NAMED flags — `--path <value>` — each value its
// own argv element, so it can never be re-split or re-parsed.
//
// Named, not positional, and the difference is a correctness bug this replaced. Args is a
// map[string]Arg: Go randomizes map iteration and a YAML mapping carries no order anyway, so the
// order had to be imposed, and sorting the names was the obvious way. But that makes the contract
// "alphabetical by argument name", which is invisible at the call site: declare {path, find, replace}
// and the script receives find, path, replace. A script written to the order its author wrote the
// YAML in gets its arguments SILENTLY transposed — no error at load, no error at run, just a tool
// that reads one value as another. Renaming an arg reorders argv the same silent way.
//
// Flags remove the class: order stops carrying meaning, `ps` shows which value is which, and a script
// that asks for a flag nobody passes fails loudly instead of quietly reading its neighbour.
//
// Still sorted, because the argv must be deterministic — the audit replays decisions, and "same
// recipe + same call -> same invocation" has to hold at the tool boundary too.
func (t Tool) argNamesAsFlags() []string {
	names := make([]string, 0, len(t.Args))
	for n := range t.Args {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]string, 0, 2*len(names))
	for _, n := range names {
		out = append(out, "--"+n, "{"+n+"}")
	}
	return out
}

// ArgNames returns the tool's declared argument names, sorted.
func (t Tool) ArgNames() []string {
	names := make([]string, 0, len(t.Args))
	for n := range t.Args {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
