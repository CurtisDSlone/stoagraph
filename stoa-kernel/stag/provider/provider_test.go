package provider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/stag/provider"
)

type fake struct {
	name  string
	items []provider.ContextItem
	err   error
}

func (f fake) Name() string { return f.name }
func (f fake) Provide(_ context.Context, _ string) ([]provider.ContextItem, error) {
	return f.items, f.err
}

func TestGatherStampsUntrusted(t *testing.T) {
	ctx := context.Background()
	providers := []provider.ContextProvider{
		fake{name: "runbooks", items: []provider.ContextItem{{Text: "claims trusted", Trust: "authoritative"}}},
		fake{name: "tickets", items: []provider.ContextItem{{Source: "T-1", Text: "ticket"}}},
	}
	items, errs := provider.Gather(ctx, "q", providers)
	if len(items) != 2 || len(errs) != 0 {
		t.Fatalf("gather: %d items, %+v errs", len(items), errs)
	}
	for _, it := range items {
		if it.Trust != provider.Untrusted {
			t.Errorf("every item must be untrusted, got %q for %+v", it.Trust, it)
		}
	}
	if items[0].Source != "runbooks" { // empty source filled with provider name
		t.Errorf("empty source should be the provider name: %q", items[0].Source)
	}
	if items[1].Source != "T-1" { // set source kept
		t.Errorf("set source should be kept: %q", items[1].Source)
	}
}

func TestGatherFailsOpen(t *testing.T) {
	ctx := context.Background()
	providers := []provider.ContextProvider{
		fake{name: "a", items: []provider.ContextItem{{Text: "one"}}},
		fake{name: "down", err: errors.New("connection refused")},
		fake{name: "b", items: []provider.ContextItem{{Text: "two"}}},
	}
	items, errs := provider.Gather(ctx, "q", providers)
	if len(items) != 2 {
		t.Errorf("good providers still run: %d items", len(items))
	}
	if len(errs) != 1 || errs[0].Provider != "down" {
		t.Errorf("failing provider reported: %+v", errs)
	}
}

func TestHTTPAdapter(t *testing.T) {
	ctx := context.Background()
	var gotQ, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQ, gotMethod = r.URL.Query().Get("q"), r.Method
		_, _ = w.Write([]byte("runbook text"))
	}))
	defer srv.Close()

	h := provider.HTTP{ProviderName: "docs", URL: srv.URL, Client: srv.Client()}
	items, err := h.Provide(ctx, "cpu spike")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Source != "docs" || items[0].Text != "runbook text" {
		t.Fatalf("http item: %+v", items)
	}
	if gotMethod != "GET" || gotQ != "cpu spike" {
		t.Errorf("server saw method=%q q=%q", gotMethod, gotQ)
	}

	// 500 -> error (Gather would skip+report it)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if _, err := (provider.HTTP{ProviderName: "x", URL: bad.URL, Client: bad.Client()}).Provide(ctx, "q"); err == nil {
		t.Error("non-2xx must error")
	}
}

func FuzzGatherUntrusted(f *testing.F) {
	f.Add("authoritative", "", "some text", false)
	f.Add("untrusted", "src", "more", false)
	f.Add("", "", "", true)
	f.Fuzz(func(t *testing.T, trust, source, text string, fail bool) {
		var p provider.ContextProvider
		if fail {
			p = fake{name: "p", err: errors.New("boom")}
		} else {
			p = fake{name: "p", items: []provider.ContextItem{{Trust: trust, Source: source, Text: text}}}
		}
		items, errs := provider.Gather(context.Background(), "q", []provider.ContextProvider{p})

		if fail {
			if len(items) != 0 || len(errs) != 1 || errs[0].Provider != "p" {
				t.Fatalf("failing provider: %d items, %+v errs", len(items), errs)
			}
			return
		}
		if len(items) != 1 {
			t.Fatalf("want 1 item, got %d", len(items))
		}
		if items[0].Trust != provider.Untrusted {
			t.Fatalf("UNTRUSTED-STAMP BREACH: item trust %q (claimed %q)", items[0].Trust, trust)
		}
		if items[0].Source == "" {
			t.Fatalf("source must be non-empty (provider name fallback)")
		}
		if items[0].Text != text {
			t.Fatalf("text not faithful: %q != %q", items[0].Text, text)
		}
	})
}
