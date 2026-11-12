package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/store"
)

type fixtureFeed struct {
	entries []feed.Entry
	err     error
}

func (f *fixtureFeed) Catalog(_ context.Context, key string) (feed.Entry, error) {
	if key != "fixture-secret" {
		return feed.Entry{}, errors.New("unexpected key")
	}
	return feed.Entry{}, f.err
}

func (f *fixtureFeed) Download(ctx context.Context, key string) ([]feed.Entry, error) {
	_, err := f.Catalog(ctx, key)
	return f.entries, err
}

func TestFeedAPIAndLastGoodSnapshot(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "gfw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db, "admin-token", "")
	path := filepath.Join(dir, "feed")
	if err = s.EnableFeed(path); err != nil {
		t.Fatal(err)
	}
	source := &fixtureFeed{entries: []feed.Entry{{
		Name: "ips.txt", Count: 120, SHA256: "first", Raw: []byte("raw"),
		Normalized: []byte("normalized"),
	}}}
	s.feed.client = source
	handler := s.Handler()
	do := func(method, path, body string, auth bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/api/v1/feed"+path, strings.NewReader(body))
		if auth {
			r.Header.Set("Authorization", "Bearer admin-token")
		}
		handler.ServeHTTP(w, r)
		if w.Code != status || strings.Contains(w.Body.String(), "fixture-secret") {
			t.Fatalf("%s %s = %d %s", method, path, w.Code, w.Body)
		}
		return w
	}
	do("GET", "", "", false, http.StatusUnauthorized)
	do("PUT", "", `{"revision":1,"key":"fixture-secret","interval_hours":0}`, true, 200)
	do("PUT", "", `{"revision":1,"interval_hours":2}`, true, 409)
	ciphertext, err := os.ReadFile(filepath.Join(path, feedSettingsFile))
	if err != nil || bytes.Contains(ciphertext, []byte("fixture-secret")) {
		t.Fatal("key was not saved encrypted", err)
	}
	do("POST", "/check", "", true, 200)
	do("POST", "/refresh", "{}", true, 200)
	source.err = errors.New("feed offline")
	do("POST", "/refresh", "{}", true, 502)
	source.err = nil
	source.entries = []feed.Entry{{Name: "ips.txt", Count: 1, SHA256: "second", Raw: []byte("short")}}
	do("POST", "/refresh", "{}", true, 502)
	if w := do("GET", "/files/ips.txt?normalized=1", "", true, 200); w.Body.String() != "normalized" {
		t.Fatal(w.Body.String())
	}
	do("GET", "/files/ips.txt", "", false, 401)
	do("POST", "/refresh", `{"accept_shrink":true}`, true, 200)
	if w := do("GET", "/files/ips.txt", "", true, 200); w.Body.String() != "short" {
		t.Fatal(w.Body.String())
	}
	restarted := New(db, "admin-token", "")
	if err = restarted.EnableFeed(path); err != nil || restarted.feed.current().Key != "fixture-secret" {
		t.Fatal("saved key did not survive restart", err)
	}
	do("PUT", "", `{"revision":2,"remove_key":true,"interval_hours":0}`, true, 200)
	do("POST", "/refresh", "{}", true, 400)
	do("GET", "/files/ips.txt", "", true, 200)
}

func TestStageFeedUsesPinnedProjectionAndDraftRevision(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "gfw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db, "admin-token", "")
	if err = s.EnableFeed(filepath.Join(dir, "feed")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash := strings.Repeat("a", 64)
	if err = db.RecordFeedAttempt(ctx, 1, "system", "", []feed.Entry{
		{Name: "ips.txt", SHA256: hash, Count: 1, Raw: []byte("192.0.2.2"), Normalized: []byte("192.0.2.2/32\n")},
		{Name: "domains.txt", SHA256: hash, Count: 1, Raw: []byte("blocked.example"), Normalized: []byte("blocked.example\n")},
	}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	post := func(consumer, body string, status int) {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/v1/feed/consumers/"+consumer, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s got %d: %s", consumer, w.Code, w.Body)
		}
	}
	post("firewall", `{"revision":1,"sha256":"`+strings.Repeat("b", 64)+`"}`, 409)
	post("firewall", `{"revision":1,"sha256":"`+hash+`","exceptions":["192.0.2.2"]}`, 200)
	post("dns", `{"revision":1,"sha256":"`+hash+`","exceptions":["Safe.Blocked.Example."]}`, 200)
	post("dns", `{"revision":1,"disable":true}`, 409)
	fw, err := db.Read(ctx)
	if err != nil || fw.Config.SecurityFeed == nil || fw.Config.SecurityFeed.Exceptions[0] != "192.0.2.2/32" {
		t.Fatalf("unexpected firewall: %+v, %v", fw, err)
	}
	dns, err := db.ReadServices(ctx)
	if err != nil || dns.Config.DNS.SecurityFeed == nil || dns.Config.DNS.SecurityFeed.Exceptions[0] != "safe.blocked.example" {
		t.Fatalf("unexpected DNS: %+v, %v", dns, err)
	}
	if err := db.RecordFeedAttempt(ctx, 1, "system", "", []feed.Entry{{
		Name: "ips.txt", SHA256: strings.Repeat("c", 64), Count: 1, Raw: []byte("203.0.113.10"), Normalized: []byte("203.0.113.10/32\n"),
	}}); err != nil {
		t.Fatal(err)
	}
	fw, err = db.Read(ctx)
	if err != nil || fw.Config.SecurityFeed == nil || fw.Config.SecurityFeed.SHA256 != hash {
		t.Fatal("fetch changed a staged version", err)
	}
	post("dns", `{"revision":2,"disable":true}`, 200)
	dns, err = db.ReadServices(ctx)
	if err != nil || dns.Config.DNS.SecurityFeed != nil {
		t.Fatal("DNS draft did not disable the filter", err)
	}
}
