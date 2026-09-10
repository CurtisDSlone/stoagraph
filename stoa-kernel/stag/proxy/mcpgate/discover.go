package mcpgate

// file-kw: mcp discover admin client tools-list downstream stdio http transport quarantined

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Auth is a downstream server's client credential (Planning/28). It applies to HTTP transports only
// (a stdio subprocess authenticates via the proxy's process env). Scheme "none"/"" = no auth. The
// gate holds the credential so the agent never does (credential isolation). The oauth scheme is
// resolved to a fresh bearer token BEFORE Connect (see the oauth package); mcpgate never sees "oauth".
type Auth struct {
	Scheme     string // none | bearer | header | query  (oauth is resolved to bearer upstream)
	Header     string // header scheme: the header name; query scheme: the query-param name
	Credential string // the resolved secret
}

// authRoundTripper injects a static credential header on every request to the downstream.
type authRoundTripper struct {
	header, value string
	next          http.RoundTripper
}

func (a authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(a.header, a.value)
	return a.next.RoundTrip(r)
}

// DiscoveredTool is a tool found on a downstream MCP server's tools/list.
type DiscoveredTool struct {
	Name        string
	Description string
	InputSchema string // JSON schema, marshaled
}

// DiscoverTools connects to a downstream MCP server and lists its tools — the admin
// operation that populates the config store. kind "stdio" runs `target` as a command
// and speaks MCP over its stdio; kind "http" connects to the target URL (with auth).
func DiscoverTools(ctx context.Context, kind, target string, a Auth) ([]DiscoveredTool, error) {
	t, err := TransportFor(kind, target, a)
	if err != nil {
		return nil, err
	}
	return Discover(ctx, t)
}

// TransportFor builds the client transport for a downstream server config. For an HTTP downstream it
// injects the configured credential (bearer/header) — FAIL CLOSED: a scheme that needs a credential
// which is empty returns an error, so the proxy never silently connects unauthenticated.
func TransportFor(kind, target string, a Auth) (mcp.Transport, error) {
	switch kind {
	case "stdio":
		fields := strings.Fields(target)
		if len(fields) == 0 {
			return nil, fmt.Errorf("mcpgate: empty stdio command")
		}
		cmd := exec.Command(fields[0], fields[1:]...)
		// A stdio server is a CHILD of the gate, and exec.Command with a nil Env inherits the gate's
		// entire environment — which holds STAG_DISPATCH_TOKEN. A downstream tool server could read it
		// and bind its OWN sessions to ANY recipe: the thing being gated would be able to grant itself
		// whatever tools it liked. Strip the control plane before handing over the process.
		//
		// The rest of the env is deliberately KEPT: a stdio server legitimately authenticates to its own
		// target from the environment (GITHUB_TOKEN, KUBECONFIG…). Only the gate's own authority goes.
		cmd.Env = scrubControlPlane(os.Environ())
		return &mcp.CommandTransport{Command: cmd}, nil
	case "http":
		// Streamable HTTP — the CURRENT MCP remote transport.
		ep, hc, err := httpAuth(target, a)
		if err != nil {
			return nil, err
		}
		return &mcp.StreamableClientTransport{Endpoint: ep, HTTPClient: hc}, nil
	case "sse":
		// SSE — the LEGACY MCP remote transport, still what a large part of the deployed ecosystem
		// speaks. It is the same HTTP hop with the same credential handling; only the framing differs,
		// which is exactly why the auth above is shared rather than reimplemented here.
		ep, hc, err := httpAuth(target, a)
		if err != nil {
			return nil, err
		}
		return &mcp.SSEClientTransport{Endpoint: ep, HTTPClient: hc}, nil
	default:
		return nil, fmt.Errorf("mcpgate: unknown transport kind %q (want stdio, http or sse)", kind)
	}
}

// httpAuth resolves the credential for a REMOTE downstream into the HTTP client (and, for the query
// scheme, the endpoint) its transport should use. Shared by streamable-HTTP and SSE: authentication is
// a property of the HTTP hop, not of the MCP framing carried over it.
//
// FAIL CLOSED: a scheme that needs a credential and has none is an error, so the gate never silently
// connects to a downstream unauthenticated and then reports its tools as though they were reachable.
// A nil client means "no auth" — the transport then uses the default.
// kw: http auth bearer header query oauth fail-closed shared streamable sse
func httpAuth(target string, a Auth) (endpoint string, client *http.Client, err error) {
	if target == "" {
		return "", nil, fmt.Errorf("mcpgate: empty http endpoint")
	}
	switch a.Scheme {
	case "", "none":
		return target, nil, nil
	case "bearer":
		if a.Credential == "" {
			return "", nil, fmt.Errorf("mcpgate: bearer auth configured but credential is empty (check secret / secret_env)")
		}
		return target, &http.Client{Transport: authRoundTripper{"Authorization", "Bearer " + a.Credential, http.DefaultTransport}}, nil
	case "header":
		if a.Header == "" {
			return "", nil, fmt.Errorf("mcpgate: header auth needs a header name")
		}
		if a.Credential == "" {
			return "", nil, fmt.Errorf("mcpgate: header auth configured but credential is empty (check secret / secret_env)")
		}
		return target, &http.Client{Transport: authRoundTripper{a.Header, a.Credential, http.DefaultTransport}}, nil
	case "query":
		// API key passed as a URL query param (e.g. Alpha Vantage's ?apikey=). The key lives ONLY in
		// the runtime endpoint here, never in the stored/displayed target — so it stays gate-side.
		if a.Header == "" {
			return "", nil, fmt.Errorf("mcpgate: query auth needs a parameter name (e.g. apikey)")
		}
		if a.Credential == "" {
			return "", nil, fmt.Errorf("mcpgate: query auth configured but credential is empty (check secret / secret_env)")
		}
		u, perr := url.Parse(target)
		if perr != nil {
			return "", nil, fmt.Errorf("mcpgate: invalid http endpoint %q: %w", target, perr)
		}
		q := u.Query()
		q.Set(a.Header, a.Credential)
		u.RawQuery = q.Encode()
		return u.String(), nil, nil
	case "oauth":
		return "", nil, fmt.Errorf("mcpgate: oauth must be resolved to a bearer token before connect (call oauth.Store.Bearer)")
	default:
		return "", nil, fmt.Errorf("mcpgate: unknown auth scheme %q", a.Scheme)
	}
}

// Connect dials a downstream MCP server and returns a LIVE client session plus its tools and resources
// (ready for NewGatingServer). The caller OWNS the session and must Close it. Unlike Discover (which
// lists then closes), the gating proxy keeps this session open to forward cleared calls. Fail-closed:
// any connect/list-tools error returns no session.
func Connect(ctx context.Context, kind, target string, a Auth) (*mcp.ClientSession, []*mcp.Tool, []*mcp.Resource, error) {
	t, err := TransportFor(kind, target, a)
	if err != nil {
		return nil, nil, nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "stag-proxy", Version: "0.1"}, nil)
	sess, err := client.Connect(ctx, t, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mcpgate: connect downstream: %w", err)
	}
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		_ = sess.Close()
		return nil, nil, nil, fmt.Errorf("mcpgate: list downstream tools: %w", err)
	}
	return sess, res.Tools, listResources(ctx, sess), nil
}

// listResources reads a downstream's resources, and is DELIBERATELY forgiving: most MCP servers are
// tools-only and answer resources/list with "method not found". That is not an error worth failing a
// connection over — it just means the server has no READ surface. A server that HAS resources gets them
// served; one that does not is unaffected.
// kw: resources list optional non-fatal tools-only
func listResources(ctx context.Context, sess *mcp.ClientSession) []*mcp.Resource {
	res, err := sess.ListResources(ctx, nil)
	if err != nil || res == nil {
		return nil
	}
	return res.Resources
}

// Discover connects a client over t, lists the server's tools, and returns them.
// Transport-agnostic so it can be driven by an in-memory transport in tests.
func Discover(ctx context.Context, t mcp.Transport) ([]DiscoveredTool, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "stag-admin", Version: "0.1"}, nil)
	sess, err := client.Connect(ctx, t, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpgate: connect: %w", err)
	}
	defer sess.Close()
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpgate: list tools: %w", err)
	}
	out := make([]DiscoveredTool, 0, len(res.Tools))
	for _, tl := range res.Tools {
		schema := ""
		if tl.InputSchema != nil {
			if b, mErr := json.Marshal(tl.InputSchema); mErr == nil {
				schema = string(b)
			}
		}
		out = append(out, DiscoveredTool{Name: tl.Name, Description: tl.Description, InputSchema: schema})
	}
	return out, nil
}

// controlPlaneVars are the gate's OWN secrets. A downstream tool server must never see them: holding
// `dispatch` lets a process bind sessions to any recipe, and holding `approve` lets it release its own
// escalations. Both would make the gate's authority available to the thing it is gating.
var controlPlaneVars = []string{
	"STAG_ADMIN_TOKEN",
	"STAG_APPROVE_TOKEN",
	"STAG_DISPATCH_TOKEN",
	"STAG_CONSOLE_TOKEN",
	"HARNESS_OPERATOR_TOKEN",
}

// scrubControlPlane returns env with the gate's control-plane secrets removed. Everything else is
// preserved — a stdio server still authenticates to its own target from the environment.
// kw: scrub control-plane env stdio subprocess secret leak
func scrubControlPlane(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(controlPlaneVars, name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}
