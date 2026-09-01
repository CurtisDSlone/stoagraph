// Package provider is the READ channel of the dual proxy (Planning/17/18): context
// providers behind one interface, with the load-bearing guarantee that ALL context
// is stamped untrusted at origin, unbypassably. A provider yields ContextItems for a
// query; Gather runs a set of providers and FORCES every item's trust to untrusted —
// a provider cannot hand back trusted-looking context. Reads are label+record, not
// deny: a provider that errors contributes nothing and is reported, not fatal.
package provider

// file-kw: context provider read channel untrusted gather label-at-origin fail-open http adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/internal/record"
)

// Untrusted is the only trust class context ever carries — enforced by Gather.
const Untrusted = "untrusted"

// ReadEvent is the audit record of one READ crossing (Planning/30): a resources/read on a context
// provider. Reads are label+record, not deny — this is the "record" half. Provider/Query/Items are
// always set; Sources names each returned item's origin; Errors carries any provider failures (reads
// are fail-open, so an error is recorded, not fatal).
// kw: read event audit provider query items sources read-channel crossing
type ReadEvent struct {
	Provider string   `json:"provider"`
	Query    string   `json:"query"`
	Items    int      `json:"items"`
	Sources  []string `json:"sources,omitempty"`
	// ItemHashes is the sha256 (hex) of each returned item's text, in the order returned. It is what
	// makes a read EVIDENCE rather than a count: the record attests the exact bytes the model saw, so
	// "the agent read these facts" is verifiable, not merely asserted. A later re-read that returns
	// different bytes produces a different hash.
	ItemHashes []string `json:"item_hashes,omitempty"`
	// QueryTruncated is set when the outbound query was capped before it reached the provider (the
	// READ-side egress bound): the recorded Query is the capped value, and this flags that a longer
	// one was refused.
	QueryTruncated bool     `json:"query_truncated,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

// Hash is the canonical hash of a read crossing, so the READ audit log can be hash-chained like the
// decision log. It covers the provider, the (already-bounded) query, the item count and per-item
// content hashes, the truncation flag, and any provider errors — everything that says WHAT was read.
// kw: read event hash evidence content-addressed chainable
func (e ReadEvent) Hash() (string, error) {
	return record.CanonicalHash(map[string]any{
		"provider":        e.Provider,
		"query":           e.Query,
		"items":           e.Items,
		"sources":         e.Sources,
		"item_hashes":     e.ItemHashes,
		"query_truncated": e.QueryTruncated,
		"errors":          e.Errors,
	})
}

// HashText is the content hash of one returned item, for ReadEvent.ItemHashes. Exported so the gate
// (mcpgate) hashes the exact text it frames and returns to the agent.
func HashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// MaxQueryLen bounds the outbound context query (the READ-side egress channel). The `?q` on a
// context read is agent-influenced text flowing OUT to the provider's endpoint; an unbounded query
// is an exfiltration channel. The gate caps it to this many bytes before Gather and records whether
// it truncated. This is the safe default ("bounded"); a per-binding "none"/"verbatim" policy is a
// later refinement (Planning/33).
const MaxQueryLen = 512

// BoundQuery caps a query to MaxQueryLen bytes (on a UTF-8 boundary), returning the capped value and
// whether it was truncated.
func BoundQuery(q string) (string, bool) {
	if len(q) <= MaxQueryLen {
		return q, false
	}
	cut := MaxQueryLen
	for cut > 0 && !utf8.RuneStart(q[cut]) {
		cut--
	}
	return q[:cut], true
}

// kw: context item source text trust score
type ContextItem struct {
	Source string
	Text   string
	Trust  string
	Score  float64
}

// kw: context provider name provide query items
type ContextProvider interface {
	Name() string
	Provide(ctx context.Context, query string) ([]ContextItem, error)
}

// kw: provider error name reason
type ProviderError struct {
	Provider string
	Err      string
}

// kw: gather run providers stamp untrusted fail-open per-provider
func Gather(ctx context.Context, query string, providers []ContextProvider) ([]ContextItem, []ProviderError) {
	var items []ContextItem
	var errs []ProviderError
	for _, p := range providers {
		got, err := p.Provide(ctx, query)
		if err != nil {
			// read fail-open: a failing source is skipped and reported, not fatal.
			errs = append(errs, ProviderError{Provider: p.Name(), Err: err.Error()})
			continue
		}
		for _, it := range got {
			it.Trust = Untrusted // UNBYPASSABLE label-at-origin — override whatever the provider set
			if it.Source == "" {
				it.Source = p.Name()
			}
			items = append(items, it)
		}
	}
	return items, errs
}

const defaultTimeout = 30 * time.Second

// kw: http provider name url client fetch body untrusted
type HTTP struct {
	ProviderName string
	URL          string
	Client       *http.Client
}

// kw: http name
func (h HTTP) Name() string { return h.ProviderName }

// kw: http provide get url query param body one item data
func (h HTTP) Provide(ctx context.Context, query string) ([]ContextItem, error) {
	u, err := url.Parse(h.URL)
	if err != nil {
		return nil, fmt.Errorf("provider %s: url: %w", h.ProviderName, err)
	}
	q := u.Query()
	q.Set("q", query) // the query is a PARAMETER, never executed
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("provider %s: request: %w", h.ProviderName, err)
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", h.ProviderName, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("provider %s: read: %w", h.ProviderName, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider %s: status %d", h.ProviderName, resp.StatusCode)
	}
	// the body is DATA; Gather stamps it untrusted.
	return []ContextItem{{Source: h.ProviderName, Text: string(body)}}, nil
}

// MaxBundleBytes caps a static bundle's total size. A bundle that cannot fit a context window is a
// configuration error caught at registration, not a runtime surprise.
const MaxBundleBytes = 1 << 20 // 1 MiB

// staticFile is one file of a content-addressed bundle: its bundle-relative path and its
// LF-canonicalized bytes.
type staticFile struct {
	rel  string
	text string
}

// Static is a content-addressed local bundle (Planning/33, C1): a file or directory of runbooks /
// reference docs the operator registered, served VERBATIM with NO query — no retrieval, no
// filtering, no outbound anything, which removes the READ-side egress channel entirely. Whole-doc
// beats similarity search at runbook scale. Every file is stamped untrusted at origin like all
// context; the read record's per-item content hashes plus this bundle's hash make the audit say
// "the model saw exactly these bytes."
type Static struct {
	ProviderName string
	files        []staticFile
	bundleHash   string
}

// kw: static name
func (s Static) Name() string { return s.ProviderName }

// Provide returns every file in the bundle as an untrusted ContextItem. The query is IGNORED (a
// static bundle has no `?q`): the whole bundle is the context.
func (s Static) Provide(_ context.Context, _ string) ([]ContextItem, error) {
	out := make([]ContextItem, 0, len(s.files))
	for _, f := range s.files {
		out = append(out, ContextItem{Source: f.rel, Text: f.text})
	}
	return out, nil
}

// BundleHash is the sha256 (hex) over the canonical manifest (sorted rel-path + per-file content
// hash). Stable across re-reads of identical content; a change to any file changes it. This is the
// value a provider row stores and a read record can carry for whole-bundle attestation.
func (s Static) BundleHash() string { return s.bundleHash }

// NewStatic reads a file or directory into a content-addressed bundle, fail-closed: an unreadable
// path, or a total size over MaxBundleBytes, is a registration error (not a silent empty bundle).
// Text is LF-canonicalized so the hash is stable across platforms; files are sorted by rel-path so
// the manifest (and thus the bundle hash) is deterministic.
func NewStatic(name, root string) (Static, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Static{}, fmt.Errorf("provider %s: static path: %w", name, err)
	}
	var files []staticFile
	var total int64
	add := func(rel, abs string) error {
		b, rerr := os.ReadFile(abs)
		if rerr != nil {
			return fmt.Errorf("provider %s: read %s: %w", name, rel, rerr)
		}
		total += int64(len(b))
		if total > MaxBundleBytes {
			return fmt.Errorf("provider %s: static bundle exceeds %d bytes (a bundle must fit a context window)", name, MaxBundleBytes)
		}
		files = append(files, staticFile{rel: rel, text: strings.ReplaceAll(string(b), "\r\n", "\n")})
		return nil
	}
	if info.IsDir() {
		werr := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			return add(filepath.ToSlash(rel), p)
		})
		if werr != nil {
			return Static{}, werr
		}
	} else {
		if err := add(filepath.Base(root), root); err != nil {
			return Static{}, err
		}
	}
	if len(files) == 0 {
		return Static{}, fmt.Errorf("provider %s: static bundle is empty", name)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })

	// bundle hash over the canonical manifest: each file's rel-path + content hash, in sorted order.
	manifest := make([]map[string]string, len(files))
	for i, f := range files {
		manifest[i] = map[string]string{"path": f.rel, "hash": HashText(f.text)}
	}
	bh, herr := record.CanonicalHash(map[string]any{"bundle": manifest})
	if herr != nil {
		return Static{}, fmt.Errorf("provider %s: bundle hash: %w", name, herr)
	}
	return Static{ProviderName: name, files: files, bundleHash: bh}, nil
}

// Skill is a content-addressed bundle that teaches a PROCEDURE (Planning/33, C3): mechanically a
// Static bundle plus a detached ed25519 signature over the bundle hash and an optional version. It is
// selected DELIBERATELY (bound by name), never similarity-retrieved. The provider only SERVES the
// bytes + signature + hash; it does not verify — the harness verifies against the operator's public
// key and decides the trust slot (signed → instruction/System, unsigned/invalid → Input). So the gate
// still asserts no trust; cryptography the reader checks does.
//
// Sidecars in the bundle root, excluded from the content and the hash:
//
//	SKILL.sig      base64 ed25519 signature over the bundle hash
//	SKILL.version  a human version label (hash stays authoritative either way)
type Skill struct {
	bundle    Static
	signature string
	version   string
}

const (
	skillSigFile     = "SKILL.sig"
	skillVersionFile = "SKILL.version"
)

// kw: skill name
func (s Skill) Name() string { return s.bundle.ProviderName }

// Provide serves the skill's bundle content (query ignored, like Static). Placement/trust is the
// harness's call after verification — a skill served through the untrusted Gather path would be
// stamped untrusted, so a signed skill is resolved by the harness DIRECTLY, not via Gather.
func (s Skill) Provide(ctx context.Context, q string) ([]ContextItem, error) {
	return s.bundle.Provide(ctx, q)
}

// BundleHash is the content identity the signature attests.
func (s Skill) BundleHash() string { return s.bundle.BundleHash() }

// Signature is the base64 ed25519 signature over the bundle hash ("" for an unsigned skill).
func (s Skill) Signature() string { return s.signature }

// Version is the human version label ("" if none).
func (s Skill) Version() string { return s.version }

// Text is the full procedure: every bundle file, in canonical (sorted rel-path) order, joined. This
// is what the harness places in System (verified) or Input (unverified).
func (s Skill) Text() string {
	var b strings.Builder
	for i, f := range s.bundle.files {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(f.text)
	}
	return b.String()
}

// NewSkill reads a skill bundle: a directory whose files are the procedure, plus optional SKILL.sig
// and SKILL.version sidecars (excluded from the content and the bundle hash). Fail-closed like
// Static. The signature is NOT verified here — that is the harness's job, against the operator key.
func NewSkill(name, dir string) (Skill, error) {
	base, err := NewStatic(name, dir)
	if err != nil {
		return Skill{}, err
	}
	var sig, ver string
	kept := base.files[:0]
	for _, f := range base.files {
		switch f.rel {
		case skillSigFile:
			sig = strings.TrimSpace(f.text)
		case skillVersionFile:
			ver = strings.TrimSpace(f.text)
		default:
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		return Skill{}, fmt.Errorf("provider %s: skill bundle has no procedure files (only sidecars)", name)
	}
	// Recompute the bundle hash over the PROCEDURE files only (sidecars excluded), so the signature
	// attests the procedure, not the signature-of-itself.
	base.files = kept
	manifest := make([]map[string]string, len(kept))
	for i, f := range kept {
		manifest[i] = map[string]string{"path": f.rel, "hash": HashText(f.text)}
	}
	bh, herr := record.CanonicalHash(map[string]any{"bundle": manifest})
	if herr != nil {
		return Skill{}, fmt.Errorf("provider %s: skill hash: %w", name, herr)
	}
	base.bundleHash = bh
	return Skill{bundle: base, signature: sig, version: ver}, nil
}

// FromConfig builds a ContextProvider from a stored provider row (name/kind/config — Planning/30).
// Only "http" is wired in v1.1: the KB/embedder lives in a DOWNSTREAM service, so the gate proxies +
// labels + records but holds no model (the deterministic/model-free property survives). "rag" and
// "mcp_resource" are reserved kinds that fail closed — the caller drops such a provider from the
// session (logged), never fabricates one.
func FromConfig(name, kind, config string) (ContextProvider, error) {
	switch kind {
	case "http":
		var c struct {
			URL string `json:"url"`
		}
		if config != "" {
			if err := json.Unmarshal([]byte(config), &c); err != nil {
				return nil, fmt.Errorf("provider %s: config: %w", name, err)
			}
		}
		if c.URL == "" {
			return nil, fmt.Errorf("provider %s: http config needs a url", name)
		}
		return HTTP{ProviderName: name, URL: c.URL}, nil
	case "static":
		// A content-addressed local bundle (Planning/33, C1): the operator points it at a file or
		// directory; the gate reads + hashes it at registration and serves it verbatim, no query.
		var c struct {
			Path string `json:"path"`
		}
		if config != "" {
			if err := json.Unmarshal([]byte(config), &c); err != nil {
				return nil, fmt.Errorf("provider %s: config: %w", name, err)
			}
		}
		if c.Path == "" {
			return nil, fmt.Errorf("provider %s: static config needs a path", name)
		}
		return NewStatic(name, c.Path)
	case "mcp_resource":
		// Resolved at the daemon from a CONNECTED downstream session (mcpgate.NewMCPResourceProvider),
		// not here: it needs a live MCP session, and this package is deliberately MCP-free (quarantine).
		return nil, fmt.Errorf("provider %s: mcp_resource is resolved at the daemon from a connected server, not FromConfig", name)
	default:
		return nil, fmt.Errorf("provider %s: kind %q not supported (kinds: http, static, mcp_resource; rag reserved)", name, kind)
	}
}
