// Command stoagraph is the installer and launcher: one binary that gets you from nothing to a running,
// authenticated gate.
//
//	stoagraph up      mint the secrets, pull the signed images, start, print your tokens
//	stoagraph tokens  print the control-plane tokens again
//	stoagraph down    stop
//
// WHY THIS EXISTS AND NOT A `docker run` ONE-LINER: the control plane uses role-scoped secrets, and the
// approve-capable one must never reach the orchestrator's environment — otherwise a compromised
// orchestrator could approve its own escalations. Something has to mint the secrets and hand each
// service only what it is entitled to, BEFORE anything starts. A single `docker run` cannot do that.
//
// It holds no secrets itself: it writes .env (0600) and never transmits it anywhere.
package main

// file-kw: cli installer launcher up down tokens compose ghcr role-secrets mint

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Version is stamped at build time (-ldflags "-X main.Version=v0.2.1"). It pins BOTH the images we pull
// and the compose file we fetch, so an install is reproducible instead of "whatever main looked like".
var Version = "latest"

const repoRaw = "https://raw.githubusercontent.com/curtisslone/stoagraph"

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "up":
		err = up()
	case "down":
		err = compose("down")
	case "tokens":
		err = printTokens()
	case "version":
		fmt.Println("stoagraph", Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "stoagraph:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`stoagraph — verifiable control for AI agents

  stoagraph up      mint secrets, pull the images, start, print your control-plane tokens
  stoagraph tokens  print the tokens again
  stoagraph down    stop everything
  stoagraph version

Docs: https://github.com/CurtisDSlone/stoagraph
`)
}

func up() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is required: https://docs.docker.com/get-docker/")
	}

	// 1. the compose file. If you are inside a clone we use yours; otherwise we fetch the one pinned to
	//    THIS binary's version. Nothing is embedded, so there is no copy that can silently drift.
	if _, err := os.Stat("compose.yml"); os.IsNotExist(err) {
		fmt.Printf("== fetching compose.yml (%s) ==\n", Version)
		if err := fetch("compose.yml", "compose.yml"); err != nil {
			return err
		}
	}

	// 2. the secrets. This is the step that cannot be skipped: the approve-capable secret is minted here
	//    and injected ONLY into the gate, never into the orchestrator.
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("== minting control-plane role secrets (.env, 0600) ==")
		if err := genEnv(); err != nil {
			return err
		}
	}

	// 3. the config dir the orchestrator bind-mounts. Make it OURSELVES, owned by the user.
	//
	// Docker creates a missing bind-mount source for you — as root. So on a fresh install this directory
	// appeared root-owned, and the very next thing the docs tell you to do ("copy your models.json into
	// config/") then needed sudo. Creating it first is the difference between a working quickstart and a
	// permissions puzzle.
	if err := os.MkdirAll("config", 0o755); err != nil {
		return err
	}

	// `--pull missing` does the right thing in both worlds: a user with no images pulls the signed ones
	// from GHCR; a contributor who just ran `docker compose build` uses what they built. compose.yml is
	// pull-only, and compose.override.yml (present only in a clone) adds the build blocks.
	fmt.Println("== starting (pulling signed images if needed) ==")
	if err := compose("up", "-d", "--pull", "missing"); err != nil {
		return err
	}

	fmt.Print("== waiting for the gate ")
	for i := 0; i < 60; i++ {
		if get("http://localhost:8080/health") == nil {
			break
		}
		fmt.Print(".")
		time.Sleep(time.Second)
	}
	fmt.Println(" ready ==")

	return printTokens()
}

// printTokens prints the control-plane tokens a client needs to call the API: the console/approve
// secret (author policy + release a held action) and the operator secret (connect models, dispatch
// events). Pass either as `Authorization: Bearer <token>` against stag-serve / harness-serve.
func printTokens() error {
	console, err := envToken("STAG_CONSOLE_TOKEN")
	if err != nil {
		return err
	}
	operator, err := envToken("HARNESS_OPERATOR_TOKEN")
	if err != nil {
		return err
	}
	fmt.Printf(`
  control-plane tokens (Authorization: Bearer <token>):

    gate token         (admin + approve)  %s
    orchestrator token (operator)         %s
`, console, operator)
	return nil
}

// genEnv mints THREE secrets. The split is the security boundary: the orchestrator is injected only
// `operator` + `dispatch`, and NEITHER is the console/approve secret — so a compromised orchestrator
// cannot forge a human decision. compose maps STAG_CONSOLE_TOKEN to admin AND approve on the gate.
func genEnv() error {
	var b strings.Builder
	b.WriteString("# StoaGraph control-plane secrets. Keep private; rotate by deleting this file.\n")
	for _, k := range []string{
		"STAG_CONSOLE_TOKEN",     // your gate key: author policy + approve
		"HARNESS_OPERATOR_TOKEN", // your orchestrator key: models + dispatch
		"STAG_DISPATCH_TOKEN",    // MACHINE ONLY: the orchestrator binds sessions; it cannot approve
	} {
		s, err := secret()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s=%s\n", k, s)
	}
	fmt.Fprintf(&b, "STOAGRAPH_VERSION=%s\n", Version)
	fmt.Fprintf(&b, "HOST_UID=%d\nHOST_GID=%d\n", os.Getuid(), os.Getgid())
	return os.WriteFile(".env", []byte(b.String()), 0o600)
}

func secret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func envToken(key string) (string, error) {
	b, err := os.ReadFile(".env")
	if err != nil {
		return "", fmt.Errorf("no .env here — run: stoagraph up")
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s not in .env", key)
}

func compose(args ...string) error {
	c := exec.Command("docker", append([]string{"compose"}, args...)...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// fetch pulls a file from the repo AT THIS BINARY'S VERSION — never from a moving branch, so an
// install is reproducible and reviewable.
func fetch(path, dst string) error {
	b, err := fetchBytes(path)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(dst); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(dst, b, 0o644)
}

func fetchBytes(path string) ([]byte, error) {
	// prefer the local copy when run inside a clone
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	url := fmt.Sprintf("%s/%s/%s", repoRaw, Version, path)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func get(url string) error {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
