// Command stag-tools serves a DECLARED set of local commands to an agent as MCP tools.
//
// This is how you give a model real local capability without ever giving it a shell.
//
//	stag-tools -config tools.yaml            # stdio  — a local agent (or a host-run gate) spawns it
//	stag-tools -config tools.yaml -http :9300 # HTTP  — its own container; the gate proxies it
//
// TWO LAYERS, AND THEY ARE DIFFERENT:
//
//	This server constrains the SHAPE. The command is authored by you; the model only fills declared
//	{placeholder} arguments; argv goes to the OS directly, so a value like `; rm -rf /` is one argument
//	to grep, not two commands. There is no escaping to get right because nothing is ever parsed.
//
//	The GATE constrains the VALUES. Route each tool to a recipe and the model can search only for the
//	patterns you allow, read only the paths you allow.
//
// Neither is sufficient alone, which is exactly why `run_command(cmd)` is not offered here and never
// will be: no recipe can meaningfully constrain an arbitrary shell string. The granularity of the tool
// is the granularity of the control.
package main

// file-kw: cmd stag-tools local tools mcp stdio http declared no-shell gate-able

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/localtools"
)

func main() {
	configPath := flag.String("config", "tools.yaml", "the declared toolset")
	root := flag.String("root", "", "override the workspace the tools run in (container: the mounted volume)")
	httpAddr := flag.String("http", "", "serve streamable HTTP on this address (empty = stdio)")
	flag.Parse()
	log.SetOutput(os.Stderr) // stdio mode: stdout carries the protocol, nothing else

	cfg, err := localtools.Load(*configPath)
	if err != nil {
		// FAIL CLOSED. A toolset that trips a guardrail does not load at all — we do not silently drop
		// the offending tool and serve the rest, because the operator would never know.
		fmt.Fprintln(os.Stderr, "stag-tools:", err)
		os.Exit(1)
	}

	if *root != "" {
		cfg.Root = *root // the container mounts the workspace at a fixed path; one tools.yaml works in both
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "stag-tools", Version: "0.1.0"}, nil)
	names := make([]string, 0, len(cfg.Tools))
	for _, t := range cfg.Tools {
		srv.AddTool(&mcp.Tool{
			Name:        t.Name,
			Description: describe(t),
			InputSchema: schemaFor(t),
		}, handler(cfg, t))
		names = append(names, t.Name)
	}
	log.Printf("stag-tools: %d tools from %s [%s] — root %s", len(cfg.Tools), *configPath, strings.Join(names, ", "), cfg.Root)

	if *httpAddr != "" {
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		mux := http.NewServeMux()
		mux.Handle("/mcp", h)
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"ok":true}`)
		})
		log.Printf("stag-tools on %s (POST /mcp)", *httpAddr)
		if err := http.ListenAndServe(*httpAddr, mux); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

// describe tells the model what the tool does AND what it actually runs. Showing the argv is deliberate:
// the command is not a secret — it is authored by the operator, and a model that can see it proposes
// better arguments. What the model cannot do is change it.
func describe(t localtools.Tool) string {
	d := t.Description
	if d == "" {
		d = t.Name
	}
	return d
}

// schemaFor builds the MCP input schema from the DECLARED args — so the model's tool signature is
// exactly the operator's declaration, no more.
func schemaFor(t localtools.Tool) map[string]any {
	props := map[string]any{}
	var required []string
	for _, name := range t.ArgNames() {
		a := t.Args[name]
		props[name] = map[string]any{"type": "string", "description": a.Description}
		if !a.Optional {
			required = append(required, name)
		}
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}

// handler runs one declared tool. Every argument the model sends is a plain string that lands in exactly
// one argv element; anything undeclared is refused.
func handler(cfg localtools.Config, t localtools.Tool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := stringArgs(req.Params.Arguments)
		if err != nil {
			return errResult(err.Error()), nil
		}
		res, rerr := cfg.Run(ctx, t, args)
		if rerr != nil {
			return errResult(rerr.Error()), nil
		}
		out := res.Output
		if res.Truncated {
			out += fmt.Sprintf("\n\n[stag-tools: output truncated at %d KiB]", 64)
		}
		if res.ExitCode != 0 {
			out = fmt.Sprintf("[exit %d]\n%s", res.ExitCode, out)
		}
		if strings.TrimSpace(out) == "" {
			out = "[no output]"
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil
	}
}

// stringArgs flattens the model's arguments to strings. Everything a declared tool takes IS a string —
// it becomes exactly one argv element — so there is nothing structured to preserve, and nothing the
// model can smuggle through a nested type.
func stringArgs(raw json.RawMessage) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("bad arguments: %w", err)
	}
	for k, v := range m {
		switch tv := v.(type) {
		case string:
			out[k] = tv
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprint(tv)
		}
	}
	return out, nil
}

func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "stag-tools: " + msg}},
	}
}
