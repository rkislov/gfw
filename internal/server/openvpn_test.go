package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/pki"
	"github.com/rkislov/gfw/internal/store"
)

func TestOpenVPNProfileAPIAuthorizationRevisionAndRevocation(t *testing.T) {
	s, h := setup(t)
	m, e := pki.Open(filepath.Join(t.TempDir(), "pki"))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	s.PKI = m
	ca, e := m.CreateCA(pki.CARequest{Name: "CA", CommonName: "CA", Days: 365})
	if e != nil {
		t.Fatal(e)
	}
	server, e := m.Issue(pki.IssueRequest{Name: "VPN", CommonName: "vpn.example.org", CAID: ca.ID, Usage: "server", DNSNames: []string{"vpn.example.org"}, Days: 30})
	if e != nil {
		t.Fatal(e)
	}
	client, e := m.Issue(pki.IssueRequest{Name: "Alice", CommonName: "Alice", CAID: ca.ID, Usage: "client", Days: 30})
	if e != nil {
		t.Fatal(e)
	}
	p := openvpn.Profile{ID: strings.Repeat("a", 32), Name: "Office", ServerCertificateID: server.ID, ClientCertificateID: client.ID, Remote: "vpn.example.org", Port: 1194, Protocol: "udp", Routes: []string{"10.50.0.0/24"}, DNS: []string{}}
	c := openvpn.Config{Profiles: []openvpn.Profile{p}}
	body, _ := json.Marshal(c)
	auth := map[string]string{"Authorization": "Bearer " + testToken, "If-Match": `"1"`}
	for _, path := range []string{"/config", "/state"} {
		if w := request(h, "GET", "/api/v1/openvpn"+path, "", nil); w.Code != 401 {
			t.Fatal("unauthenticated read", path, w.Code)
		}
	}
	for _, path := range []string{"/export", "/check"} {
		if w := request(h, "POST", "/api/v1/openvpn"+path, "{}", nil); w.Code != 401 {
			t.Fatal("unauthenticated action", path, w.Code)
		}
	}
	if w := request(h, "PUT", "/api/v1/openvpn/config", string(body), map[string]string{"Authorization": "Bearer " + testToken}); w.Code != 428 {
		t.Fatal(w.Code)
	}
	w := request(h, "PUT", "/api/v1/openvpn/config", string(body), auth)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("config leaks key")
	}
	if w = request(h, "PUT", "/api/v1/openvpn/config", string(body), auth); w.Code != 412 {
		t.Fatal("stale write accepted", w.Code)
	}
	if w = request(h, "POST", "/api/v1/openvpn/export", `{"id":"`+p.ID+`","revision":1}`, auth); w.Code != 412 {
		t.Fatal("stale export accepted", w.Code)
	}
	w = request(h, "POST", "/api/v1/openvpn/export", `{"id":"`+p.ID+`","revision":2}`, auth)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "PRIVATE KEY") || !strings.Contains(w.Body.String(), "peer-fingerprint ") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bad private download", w.Code)
	}
	for _, path := range []string{"/config", "/state"} {
		w = request(h, "GET", "/api/v1/openvpn"+path, "", auth)
		if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatal("metadata leak", path, w.Code)
		}
	}
	// Session cookies alone must never authorize key export.
	login := request(h, "POST", "/api/v1/auth/login", `{"token":"`+testToken+`"}`, nil)
	cookie := login.Result().Cookies()[0]
	w = request(h, "POST", "/api/v1/openvpn/export", `{"id":"`+p.ID+`","revision":2}`, map[string]string{"Cookie": cookie.String()})
	if w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if _, e = m.Revoke(client.ID); e != nil {
		t.Fatal(e)
	}
	w = request(h, "POST", "/api/v1/openvpn/export", `{"id":"`+p.ID+`","revision":2}`, auth)
	if w.Code != 422 || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("revocation ignored", w.Code)
	}
	w = request(h, "GET", "/api/v1/openvpn/state", "", auth)
	if !strings.Contains(w.Body.String(), `"can_export":false`) {
		t.Fatal("wrong revoked status")
	}
	// Retain invalid existing profiles while repairing/deleting others.
	auth["If-Match"] = `"2"`
	w = request(h, "PUT", "/api/v1/openvpn/config", string(body), auth)
	if w.Code != 200 {
		t.Fatal("unchanged revoked profile prevents save", w.Code, w.Body.String())
	}
	auth["If-Match"] = `"3"`
	w = request(h, "PUT", "/api/v1/openvpn/config", `{"profiles":[]}`, auth)
	if w.Code != 200 {
		t.Fatal("cannot delete revoked profile", w.Code)
	}
}
func TestOpenVPNPersistsReferencesWithoutSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	db, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	p := openvpn.Profile{ID: strings.Repeat("a", 32), Name: "Office", ServerCertificateID: strings.Repeat("b", 32), ClientCertificateID: strings.Repeat("c", 32), Remote: "198.51.100.10", Port: 1194, Protocol: "udp"}
	saved, e := db.SaveOpenVPN(t.Context(), 1, openvpn.Config{Profiles: []openvpn.Profile{p}})
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	db, e = store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	loaded, e := db.ReadOpenVPN(t.Context())
	if e != nil || loaded.Revision != saved.Revision || len(loaded.Config.Profiles) != 1 || loaded.Config.Profiles[0].ID != p.ID {
		t.Fatal("profile not restored", e)
	}
}
