package server

import (
	"encoding/json"
	"github.com/rkislov/gfw/internal/pki"
	"path/filepath"
	"strings"
	"testing"
)

func TestPKIAuthenticatedMetadataAndPublicExport(t *testing.T) {
	s, h := setup(t)
	vault, e := pki.Open(filepath.Join(t.TempDir(), "vault"))
	if e != nil {
		t.Fatal(e)
	}
	defer vault.Close()
	s.PKI = vault
	if w := request(h, "GET", "/api/v1/pki", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated vault access", w.Code)
	}
	headers := map[string]string{"Authorization": "Bearer " + testToken}
	w := request(h, "POST", "/api/v1/pki/ca", `{"name":"CA","common_name":"Root","days":365}`, headers)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var ca pki.Certificate
	json.Unmarshal(w.Body.Bytes(), &ca)
	w = request(h, "GET", "/api/v1/pki", "", headers)
	if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("metadata leaked secret", w.Code)
	}
	w = request(h, "GET", "/api/v1/pki/certificates/"+ca.ID+"/pem", "", headers)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("public certificate export invalid", w.Code)
	}
	w = request(h, "POST", "/api/v1/pki/tls/apply", `{"id":"`+ca.ID+`","timeout_seconds":30}`, headers)
	if w.Code != 422 {
		t.Fatal("HTTP can replace panel TLS", w.Code)
	}
}
