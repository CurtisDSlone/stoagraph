package router_test

// Guard against silently dropping Sequenced when copying a route into a router.Spec.
//
// Sequenced is a bool whose ZERO VALUE DISABLES A SECURITY CONTROL. A route it is dropped from
// becomes an ordinary advertised route: the tool appears in tools/list and is directly callable,
// instead of being hidden and reachable only via a one-shot grant minted by a recipe's invoke.
// Nothing errors, nothing logs, and every route still reports valid:true — the enforcement is
// simply gone.
//
// This has been introduced FOUR separate times in this codebase, in four different files, because
// the struct literals are written field-by-field and an omitted bool is legal Go:
//
//	harness/dispatch/wiring.go     RouteSpec  (also omitted the struct FIELD, so the daemon
//	                                          received sequenced=false for every bound route)
//	cmd/stag-proxy/main.go         router.Spec — the stdio gate
//	stag/serve/serve.go            router.Spec — liveGate, the decision path of stag-serve
//	stag/proxy/sessiond/sessiond.go            (this one was correct)
//
// A compile-time guarantee would be better than a test: an explicit Reachability type with no
// meaningful zero, or a constructor that cannot be called without stating it. Until then, this
// test is the boundary — it reads the source and fails on any router.Spec literal that names
// GateArg (i.e. is copying a real route) without also naming Sequenced.
//
// kw: sequenced dropped fail-open guard router spec literal security-control zero-value

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A router.Spec literal, however it is wrapped across lines.
var specLiteral = regexp.MustCompile(`router\.Spec\{[^}]*\}`)

func TestRouterSpecLiteralsCarrySequenced(t *testing.T) {
	root := ".."
	if wd, err := os.Getwd(); err == nil {
		// stag/router -> repo root
		root = filepath.Join(wd, "..", "..")
	}

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable tree entries are not this test's business
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "bin" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, lit := range specLiteral.FindAllString(string(src), -1) {
			// A literal that does not set GateArg is not copying a stored route (test fixtures,
			// zero-value construction); only guard the ones that clearly are.
			if !strings.Contains(lit, "GateArg") {
				continue
			}
			if !strings.Contains(lit, "Sequenced") {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel+": "+collapse(lit))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("router.Spec literal(s) copy a route but drop Sequenced — a dropped Sequenced "+
			"silently turns a grant-only route into an advertised, freely callable one:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
