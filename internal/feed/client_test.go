package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const catalogFixture = `{"product":"Security Feed","domains":"/feeds/v1/domains.txt","ioc_json":"/feeds/v1/iocs.json"}`

func TestDownloadTLSAndNormalize(t *testing.T) {
	responses := map[string]string{
		"/feeds/v1/catalog.json": catalogFixture,
		"/feeds/v1/ips.txt":      "# header\n192.0.2.1\n192.0.2.1/32\n2001:db8:1::4/64\n",
		"/feeds/v1/domains.txt":  "EXAMPLE.ORG.\nexample.org\nпример.рф\n",
		"/feeds/v1/iocs.json":    `[{"type":"ip","value":"192.0.2.1","source":"test","reference":"preserve me"}]`,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "GFW/1" || r.Header.Get("X-Api-Key") != "fixture-secret" || r.URL.RawQuery != "" {
			t.Error("unexpected authentication")
		}
		w.Header().Set("X-Feed-Source", "merged")
		_, _ = w.Write([]byte(responses[r.URL.Path]))
	}))
	defer srv.Close()
	c := newClient(srv.URL, srv.Client().Transport)
	snapshot, err := c.Download(context.Background(), "fixture-secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 4 || snapshot[1].Count != 2 || string(snapshot[1].Normalized) != "192.0.2.1/32\n2001:db8:1::/64\n" ||
		string(snapshot[2].Normalized) != "example.org\nxn--e1afmkfd.xn--p1ai\n" || snapshot[3].Count != 1 ||
		string(snapshot[3].Raw) != responses["/feeds/v1/iocs.json"] || snapshot[1].Source != "merged" || len(snapshot[1].SHA256) != 64 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestRejectRedirectAndInvalidFeed(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("client followed redirect")
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := newClient(srv.URL, srv.Client().Transport)
	if _, err := c.Catalog(context.Background(), "fixture-secret"); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("unexpected redirect result: %v", err)
	}
	for _, invalid := range []string{"{}", "[]{}", `[{"type":"ip","value":"192.0.2.1"}]`} {
		if _, err := countIOCs([]byte(invalid)); !errors.Is(err, ErrInvalidData) {
			t.Fatalf("accepted invalid IOC: %s", invalid)
		}
	}
	if _, _, err := normalizeList([]byte("html garbage"), true); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("accepted invalid IP: %v", err)
	}
}

func TestNormalizeProviderDomainsWithMixedIndicators(t *testing.T) {
	var list strings.Builder
	for i := range 40 {
		fmt.Fprintf(&list, "dns-%d.example.org\n", i)
	}
	list.WriteString("https://example.org/path\n192.0.2.10\n")
	normalized, count, err := normalizeList([]byte(list.String()), false)
	if err != nil || count != 40 || bytes.Contains(normalized, []byte("192.0.2.10")) ||
		bytes.Contains(normalized, []byte("https://")) {
		t.Fatalf("unexpected mixed domain result: count=%d err=%v", count, err)
	}
	list.WriteString("malformed-indicator\n")
	if _, _, err := normalizeList([]byte(list.String()), false); !errors.Is(err, ErrInvalidData) {
		t.Fatalf("accepted excessive invalid indicators: %v", err)
	}
}

func TestWAFPackDigestAndSubscription(t *testing.T) {
	raw := []byte(`{"format":"security-feed-waf-v1"}`)
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "fixture-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/feeds/v1/waf/catalog.json":
			fmt.Fprintf(w, `{"format":"security-feed-waf-catalog-v1","packs":[{"id":"generic-web","version":"1.0.0","sha256":%q}]}`, sum)
		case "/feeds/v1/waf/packs/generic-web/1.0.0.json":
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newClient(server.URL, server.Client().Transport)
	packs, err := client.WAFCatalog(context.Background(), "fixture-key")
	if err != nil || len(packs) != 1 {
		t.Fatalf("catalog: %v, %v", packs, err)
	}
	p := packs[0]
	got, err := client.WAFPack(context.Background(), "fixture-key", p.ID, p.Version, p.SHA256)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("pack: %s, %v", got, err)
	}
	if _, err := client.WAFPack(context.Background(), "fixture-key", p.ID, p.Version, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted pack with different digest")
	}
}
