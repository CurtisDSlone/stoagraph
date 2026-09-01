package argpath_test

// kw-test: a gate path reaches into the PAYLOAD; composites fail closed rather than being stringified;
// every element of an array is judged, so one bad element cannot ride along with good ones

import (
	"encoding/json"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/proxy/argpath"
)

// The push_files shape: the scalars are the harmless part and the PAYLOAD is where the risk lives.
// Under the old fmt.Sprint reader this whole array arrived as "[map[content:... path:...]]" and no
// rule could judge it, so the file contents crossed ungoverned while owner/repo were carefully gated.
const pushFiles = `{
  "owner": "acme",
  "repo": "app",
  "files": [
    {"path": "src/a.go", "content": "package a"},
    {"path": "../../etc/passwd", "content": "boom"}
  ],
  "reviewers": ["alice", "bob"],
  "replicas": 3,
  "dry_run": true
}`

func TestExtractsScalarsAndPayloadLeaves(t *testing.T) {
	raw := json.RawMessage(pushFiles)
	for _, c := range []struct {
		path string
		want []string
	}{
		{"owner", []string{"acme"}},
		{"replicas", []string{"3"}},               // canonical: 3, not 3e+00
		{"dry_run", []string{"true"}},             //
		{"reviewers[]", []string{"alice", "bob"}}, // every element of a scalar array
		// THE POINT: reach into the payload. Both files are judged, in document order.
		{"files[].path", []string{"src/a.go", "../../etc/passwd"}},
		{"files[].content", []string{"package a", "boom"}},
	} {
		got, err := argpath.Extract(raw, c.path)
		if err != nil {
			t.Fatalf("Extract(%q): %v", c.path, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("Extract(%q) = %v, want %v", c.path, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Extract(%q)[%d] = %q, want %q", c.path, i, got[i], c.want[i])
			}
		}
	}
}

// A path landing on a composite must be an ERROR, not a stringified approximation. This is the whole
// reason the package exists: the old reader answered "[map[...]]" and a set_membership rule then
// compared against that, which is judging Go's memory layout, not the agent's request.
func TestCompositesFailClosed(t *testing.T) {
	raw := json.RawMessage(pushFiles)
	for _, path := range []string{
		"files",   // an array, without []
		"files[]", // an array OF OBJECTS — the element is still a composite
	} {
		if got, err := argpath.Extract(raw, path); err == nil {
			t.Errorf("Extract(%q) = %v, want an error — a policy cannot judge a composite", path, got)
		}
	}
}

// Absent, null and empty bind "" — which no allow-set contains, so they are DENIED. A missing value is
// not a permissive value.
func TestAbsentBindsEmptyAndFailsClosed(t *testing.T) {
	for _, c := range []struct{ raw, path string }{
		{`{"a":"x"}`, "nope"},            // absent key
		{`{"a":null}`, "a"},              // explicit null
		{`{"o":{}}`, "o.deep"},           // absent nested key
		{`{"files":[]}`, "files[].path"}, // empty array selects nothing
		{`{}`, "anything"},               // no args at all
	} {
		got, err := argpath.Extract(json.RawMessage(c.raw), c.path)
		if err != nil {
			t.Fatalf("Extract(%s, %q): unexpected error %v", c.raw, c.path, err)
		}
		if len(got) != 1 || got[0] != "" {
			t.Errorf("Extract(%s, %q) = %v, want [\"\"] so it fails any allow-set", c.raw, c.path, got)
		}
	}
}

// Extraction is deterministic: the audit value and the decision must not depend on map iteration order.
func TestDeterministic(t *testing.T) {
	raw := json.RawMessage(pushFiles)
	first, err := argpath.Extract(raw, "files[].path")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := argpath.Extract(raw, "files[].path")
		if err != nil {
			t.Fatal(err)
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("nondeterministic extraction: %v then %v", first, again)
			}
		}
	}
}

// A path into a nested object, which is how a tool like issue_write hides its real payload.
func TestNestedObjectPath(t *testing.T) {
	raw := json.RawMessage(`{"issue_fields":{"title":"hi","body":"there"}}`)
	got, err := argpath.Extract(raw, "issue_fields.title")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "hi" {
		t.Fatalf("got %v, want [hi]", got)
	}
}

// Fuzz the enforcement path: extraction must never panic, and must never invent a value. Whatever the
// arguments are, the result is either an error (deny) or a list of strings — never a crash.
func FuzzExtract(f *testing.F) {
	f.Add(pushFiles, "files[].path")
	f.Add(`{"a":1}`, "a")
	f.Add(`not json`, "a")
	f.Add(`{"a":{"b":[{"c":"d"}]}}`, "a.b[].c")
	f.Fuzz(func(t *testing.T, raw, path string) {
		vals, err := argpath.Extract(json.RawMessage(raw), path)
		if err != nil {
			if vals != nil {
				t.Fatalf("an error must yield no values, got %v", vals)
			}
			return // an error is a DENY, which is always a safe answer
		}
		if len(vals) == 0 {
			t.Fatal("a successful extract must yield at least one value (\"\" when absent)")
		}
	})
}
