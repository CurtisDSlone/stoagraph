// Command stag-serve runs the HTTP API over the gating proxy (Planning/16) — the
// backend the Next.js console talks to. It is the control plane and a recipe
// SIMULATOR: /api/decide evaluates a proposed call without recording, and /api/log
// READS the tamper-evident audit that the enforcement proxy (stag-proxy) writes.
// Serves /api/decide, /api/log, /api/policies, /api/health.
package main

// file-kw: cmd stag-serve http api console backend gating proxy decide log

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/adapterauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/auth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/egress"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/oauth"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/mcpgate"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipe"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/recipestore"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/serve"
	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/store"
)

func main() {
	// A fresh instance starts CLEAN: no policy, no routes, nothing pre-trusted. Seeding a starter
	// policy would mean shipping a gate that already permits something the operator never authored —
	// exactly the wrong default for a security control. Pass -recipe to seed a demo instead.
	recipePath := flag.String("recipe", "", "OPTIONAL seed policy to author + route on first run (empty = start with an empty store)")
	tool := flag.String("tool", "write_note", "the MCP tool the seed policy governs (only with -recipe)")
	gateArg := flag.String("gate-arg", "text", "the gated argument of the seed policy (only with -recipe)")
	logPath := flag.String("log", "data/decisions.jsonl", "hash-chained egress log for cleared crossings")
	pubPath := flag.String("pub", "", "optional Ed25519 public key to verify signed checkpoints")
	// The recipe store is RUNTIME STATE, not shipped content: the gate reads AND writes it (the console's
	// editor saves .yaml here). It lives under data/ with the config DB and the audit log.
	recipesDir := flag.String("recipes-dir", "data/recipes", "recipe store (the gate reads + writes it)")
	storePath := flag.String("store", "data/config.db", "SQLite config store (routes, adapters)")
	oauthDir := flag.String("oauth-dir", "data/oauth", "per-server OAuth token store (shared with stag-proxy)")
	publicURL := flag.String("public-url", envOr("STAG_PUBLIC_URL", "http://localhost:8080"), "externally-reachable base URL of this server (for the OAuth redirect_uri)")
	approvalKey := flag.String("approval-key", "data/approval.key", "Ed25519 key for signing approval releases (auto-generated if absent)")
	approvalWebhook := flag.String("approval-webhook", os.Getenv("STAG_APPROVAL_WEBHOOK"), "optional URL POSTed a notice when the gate escalates a fresh action")
	addr := flag.String("addr", ":8080", "listen address")
	tokensPath := flag.String("tokens", "data/control.tokens", "control-plane role tokens (auto-generated 0600 if absent)")
	devNoAuth := flag.Bool("dev-no-auth", false, "DANGER: disable control-plane auth entirely (local dev only)")
	flag.Parse()

	// Create our own directories so a fresh clone (which has no data/) just works — in a container
	// there is nobody to run mkdir for us.
	for _, p := range []string{*logPath, *storePath, *tokensPath, *approvalKey} {
		die(os.MkdirAll(filepath.Dir(p), 0o755))
	}
	die(os.MkdirAll(*recipesDir, 0o755))

	// Optional seed policy. Absent (the default) => an EMPTY gate: no recipe, no route, nothing allowed.
	var seed *recipe.Parsed
	var seedSrc []byte
	if *recipePath != "" {
		src, rerr := os.ReadFile(*recipePath)
		die(rerr)
		p, perr := recipe.Parse(src)
		die(perr)
		seed, seedSrc = &p, src
	}

	// The config store drives the gate's route table (multi-tool).
	st, serr := store.Open(*storePath)
	oauthStore := oauth.Store{Dir: *oauthDir}
	die(serr)
	defer st.Close()
	ctx := context.Background()

	recipes := recipestore.Store{Dir: *recipesDir}
	// Only an explicit -recipe seed authors a policy and a route. With no seed the store and the route
	// table stay EMPTY: the gate governs nothing and forwards nothing. Fail-closed is the fresh-install
	// default too — a security control must not arrive already permitting something you never wrote.
	if seed != nil {
		if routes, _ := st.ListRoutes(ctx); len(routes) == 0 {
			if _, rerr := recipes.Save(seedSrc); rerr != nil {
				die(rerr)
			}
			die(st.PutRoute(ctx, store.Route{Tool: *tool, Recipe: seed.Header.Name, GateArg: *gateArg}))
			log.Printf("seeded: policy %q -> tool %q (gated arg %q)", seed.Header.Name, *tool, *gateArg)
		}
	}

	// stag-serve is the control plane + a recipe SIMULATOR: /api/decide answers "what would the gate
	// decide?" without recording. The canonical, tamper-evident audit is written by exactly ONE process —
	// the enforcement proxy (stag-proxy) — which owns the hash chain in *logPath. A second appender here
	// would fork that chain, so the gate carries a DiscardSink; /api/log READS *logPath to surface what
	// the proxy recorded. (Routes are resolved from the store per request; see serve.Server.liveGate.)
	gate := proxy.Gate{Sink: egress.DiscardSink{}}
	// approval signing key (Stage 5): mint signed releases. Auto-generate + persist on first run
	// (dev: unencrypted on disk is fine). Same key across restarts keeps issued tokens verifiable.
	priv, kerr := loadOrGenPriv(*approvalKey)
	die(kerr)

	// CONTROL-PLANE AUTH (Planning/31). stag-serve OWNS token generation: on first run it writes four
	// distinct role secrets (0600), so a fresh deploy is closed-by-default with zero setup. The daemon
	// and harness-serve only READ this file. -dev-no-auth bypasses everything and says so, loudly.
	tokens, generated, aerr := auth.LoadOrGenerate(*tokensPath)
	die(aerr)
	if generated {
		log.Printf("control-plane: generated four role tokens at %s (0600) — give `dispatch` to the orchestrator, keep `approve` for humans", *tokensPath)
	}
	if *devNoAuth {
		log.Printf("!!! CONTROL PLANE UNAUTHENTICATED (-dev-no-auth) — every admin/approve endpoint is wide open. NEVER use this outside local dev.")
	}

	// No seed => no policies to advertise. An empty list is the honest answer for a fresh gate.
	var policies []serve.PolicyView
	if seed != nil {
		policies = []serve.PolicyView{{Tool: *tool, Recipe: seed.Header.Name, GateArg: *gateArg}}
	}

	srv := &serve.Server{
		Gate:            gate,
		LogPath:         *logPath,
		Priv:            priv,
		Policies:        policies,
		Recipes:         recipes,
		Store:           st,
		ApprovalWebhook: *approvalWebhook,
		Auth:            &auth.Authenticator{Tokens: tokens, Disabled: *devNoAuth},
		OAuth:           oauthStore,
		PublicURL:       strings.TrimRight(*publicURL, "/"),
	}
	if *pubPath != "" {
		pub, perr := loadPub(*pubPath)
		die(perr)
		srv.Pub = pub
	}
	// wire the real MCP discovery (over the quarantined SDK) into the admin endpoints. The credential is
	// resolved through adapterauth so an oauth server yields a fresh bearer (and an unauthorized one
	// surfaces a clean "run sign-in" discovery error instead of a raw connect failure).
	srv.Discover = func(ctx context.Context, sv store.MCPServer) ([]store.MCPTool, error) {
		dauth, aerr := adapterauth.Resolve(ctx, oauthStore, nil, sv)
		if aerr != nil {
			return nil, aerr
		}
		dts, derr := mcpgate.DiscoverTools(ctx, sv.Transport, sv.Target, dauth)
		if derr != nil {
			return nil, derr
		}
		tools := make([]store.MCPTool, len(dts))
		for i, dt := range dts {
			tools[i] = store.MCPTool{Name: dt.Name, InputSchema: dt.InputSchema}
		}
		return tools, nil
	}

	log.Printf("stag-serve on %s — routes from %s, recipes in %s (log %s)", *addr, *storePath, *recipesDir, *logPath)
	die(http.ListenAndServe(*addr, srv.Handler()))
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return egress.ParsePublic(b)
}

// envOr returns the environment value for key, or def when unset/empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadOrGenPriv loads the approval signing key, generating + persisting one (0600) on first run.
func loadOrGenPriv(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return egress.ParsePrivate(b)
	}
	_, priv, err := egress.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, egress.MarshalPrivate(priv), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "stag-serve:", err)
		os.Exit(1)
	}
}
