package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/rkislov/gfw/internal/pki/acmetest"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testVault(t *testing.T) *Manager {
	t.Helper()
	m, e := Open(filepath.Join(t.TempDir(), "vault"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
func testCA(t *testing.T, m *Manager) Certificate {
	t.Helper()
	c, e := m.CreateCA(CARequest{Name: "Office CA", CommonName: "Office Root", Days: 365})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func testLeaf(t *testing.T, m *Manager, ca Certificate, name string) Certificate {
	t.Helper()
	c, e := m.Issue(IssueRequest{Name: name, CAID: ca.ID, CommonName: name, DNSNames: []string{name}, IPs: []string{"127.0.0.1"}, Usage: "server", Days: 30})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestCAIssueRevokeEncryptionAndRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	m, e := Open(root)
	if e != nil {
		t.Fatal(e)
	}
	ca := testCA(t, m)
	leaf := testLeaf(t, m, ca, "router.home.arpa")
	x, e := m.get(leaf.ID)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(x.PEM, x.Key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	raw, _ := m.PublicPEM(ca.ID)
	roots.AppendCertsFromPEM(raw)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "router.home.arpa"}); e != nil {
		t.Fatal(e)
	}
	var encrypted []byte
	if e = m.db.QueryRow("SELECT secret FROM certificates WHERE id=?", leaf.ID).Scan(&encrypted); e != nil || bytes.Contains(encrypted, []byte("PRIVATE KEY")) || bytes.Contains(encrypted, x.Key) {
		t.Fatal("key stored unencrypted", e)
	}
	if _, e = m.Revoke(leaf.ID); e != nil {
		t.Fatal(e)
	}
	crlPEM, e := m.CRL(ca.ID)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(crlPEM)
	crl, e := x509.ParseRevocationList(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	rootBlock, _ := pem.Decode(raw)
	rootCert, _ := x509.ParseCertificate(rootBlock.Bytes)
	if e = crl.CheckSignatureFrom(rootCert); e != nil || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("invalid CRL", e)
	}
	if _, e = m.pair(leaf.ID, true); e == nil {
		t.Fatal("revoked certificate usable")
	}
	if _, e = Open(root); e == nil {
		t.Fatal("second vault owner allowed")
	}
	m.Close()
	m, e = Open(root)
	if e != nil {
		t.Fatal(e)
	}
	records, e := m.List()
	if e != nil || len(records) != 2 {
		t.Fatal("vault not recovered", e)
	}
	m.Close()
	keyPath := filepath.Join(root, "device.key")
	key, _ := os.ReadFile(keyPath)
	key[0] ^= 1
	os.WriteFile(keyPath, key, 0600)
	if broken, e := Open(root); e == nil {
		broken.Close()
		t.Fatal("wrong device key accepted")
	}
}
func TestImportAndSANValidation(t *testing.T) {
	m := testVault(t)
	ca := testCA(t, m)
	a := testLeaf(t, m, ca, "a.example")
	b := testLeaf(t, m, ca, "b.example")
	one, _ := m.get(a.ID)
	two, _ := m.get(b.ID)
	if _, e := m.Import(ImportRequest{Name: "leak", CertificatePEM: string(append(append([]byte{}, one.PEM...), one.Key...)), PrivateKeyPEM: string(one.Key)}); e == nil {
		t.Fatal("private key in public PEM accepted")
	}
	if _, e := m.Import(ImportRequest{Name: "mismatch", CertificatePEM: string(one.PEM), PrivateKeyPEM: string(two.Key)}); e == nil {
		t.Fatal("mismatched key imported")
	}
	if _, e := m.Issue(IssueRequest{Name: "bad", CAID: ca.ID, CommonName: "bad", DNSNames: []string{"x;cmd"}, Usage: "server", Days: 30}); e == nil {
		t.Fatal("invalid SAN accepted")
	}
	if _, e := m.Issue(IssueRequest{Name: "too long", CAID: ca.ID, CommonName: "long", DNSNames: []string{"long.example"}, Usage: "server", Days: 397}); e == nil {
		t.Fatal("leaf outlives CA")
	}
}
func TestTLSFreshHandshakeRollbackAndConfirm(t *testing.T) {
	m := testVault(t)
	ca := testCA(t, m)
	first := testLeaf(t, m, ca, "first.example")
	second := testLeaf(t, m, ca, "second.example")
	x, _ := m.get(first.ID)
	fallback, e := tls.X509KeyPair(x.PEM, x.Key)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate}}
	defer server.Close()
	if e = m.AttachTLS(fallback, Probe(listener.Addr().String())); e != nil {
		t.Fatal(e)
	}
	go server.ServeTLS(listener, "", "")
	if _, e = m.SwitchTLS(context.Background(), second.ID, "wrong.example", 30); e == nil {
		t.Fatal("wrong SAN installed")
	}
	if _, e = m.SwitchTLS(context.Background(), second.ID, "second.example", 30); e != nil {
		t.Fatal(e)
	}
	conn, e := tls.Dial("tcp", listener.Addr().String(), &tls.Config{ServerName: "second.example", InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	if fingerprint(conn.ConnectionState().PeerCertificates[0].Raw) != second.Fingerprint {
		t.Fatal("hot reload did not reach new handshake")
	}
	conn.Close()
	now := m.now()
	m.now = func() time.Time { return now.Add(time.Minute) }
	if e = m.TickTLS(); e != nil {
		t.Fatal(e)
	}
	got, _ := m.GetCertificate(nil)
	if fingerprint(got.Certificate[0]) != first.Fingerprint {
		t.Fatal("timeout did not restore fallback")
	}
	m.now = time.Now
	if _, e = m.SwitchTLS(context.Background(), second.ID, "second.example", 30); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfirmTLS(second.ID, "second.example"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Revoke(second.ID); e == nil {
		t.Fatal("active TLS certificate revoked")
	}
	if m.TLSStatus().ActiveID != second.ID {
		t.Fatal("confirmation lost")
	}
}
func TestACMEFullOrderAndChallengeIsolation(t *testing.T) {
	m := testVault(t)
	m.EnableChallenges()
	ca := acmetest.NewCAServer(t).ChallengeTypes("http-01").Start()
	m.HTTPClient = ca.HTTPClient()
	ca.ResolveHandler("gateway.example.org", m.ChallengeHandler())
	p, e := m.CreateProfile(ProfileRequest{Name: "Public", DirectoryURL: ca.URL(), Email: "admin@example.org", Domains: []string{"gateway.example.org"}, TOSAgreed: true, RenewBeforeDays: 30})
	if e != nil {
		t.Fatal(e)
	}
	j, e := m.Queue(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m.execute(ctx, j)
	jobs, e := m.Jobs()
	if e != nil || jobs[0].Status != "issued" {
		t.Fatal("ACME order failed", jobs, e)
	}
	x, e := m.get(jobs[0].CertificateID)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := validatePair(x.PEM, x.Key, m.now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pair.Leaf.Verify(x509.VerifyOptions{Roots: ca.Roots(), DNSName: "gateway.example.org"}); e != nil {
		t.Fatal(e)
	}
	p, key, e := m.profile(p.ID)
	if e != nil || p.AccountURI == "" || !bytes.Contains(key, []byte("PRIVATE KEY")) {
		t.Fatal("account not persisted", e)
	}
	m.db.Exec("INSERT INTO acme_challenges VALUES(?,?,?,?)", "token", "gateway.example.org", "response", m.now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	for _, tc := range []struct {
		host, path string
		code       int
	}{{"gateway.example.org", "/.well-known/acme-challenge/token", 200}, {"other.example.org", "/.well-known/acme-challenge/token", 404}, {"gateway.example.org", "/api/v1/status", 404}, {"gateway.example.org", "/.well-known/acme-challenge/token/extra", 404}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		m.ChallengeHandler().ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatal(tc, w.Code)
		}
	}
	body, _ := m.PublicPEM(x.ID)
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("public export leaked key")
	}
}

func TestTLSRestartRollsBackPendingButPreservesConfirmed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	m, e := Open(root)
	if e != nil {
		t.Fatal(e)
	}
	ca := testCA(t, m)
	a := testLeaf(t, m, ca, "a.example")
	b := testLeaf(t, m, ca, "b.example")
	x, _ := m.get(a.ID)
	fallback, _ := tls.X509KeyPair(x.PEM, x.Key)
	probe := func(context.Context, *tls.Certificate, string) error { return nil }
	if e = m.AttachTLS(fallback, probe); e != nil {
		t.Fatal(e)
	}
	if _, e = m.SwitchTLS(context.Background(), a.ID, "a.example", 30); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfirmTLS(a.ID, "a.example"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.SwitchTLS(context.Background(), b.ID, "b.example", 30); e != nil {
		t.Fatal(e)
	}
	m.Close()
	m, e = Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if e = m.AttachTLS(fallback, probe); e != nil {
		t.Fatal(e)
	}
	status := m.TLSStatus()
	if status.ActiveID != a.ID || status.PendingID != "" {
		t.Fatal("pending TLS survived restart", status)
	}
	pair, _ := m.GetCertificate(nil)
	if fingerprint(pair.Certificate[0]) != a.Fingerprint {
		t.Fatal("confirmed certificate not restored")
	}
}

func TestACMERenewalPreservesPreviousOnFailure(t *testing.T) {
	m := testVault(t)
	m.EnableChallenges()
	ca := acmetest.NewCAServer(t).ChallengeTypes("http-01").Start()
	m.HTTPClient = ca.HTTPClient()
	ca.ResolveHandler("renew.example.org", m.ChallengeHandler())
	p, e := m.CreateProfile(ProfileRequest{Name: "Renew", DirectoryURL: ca.URL(), Email: "admin@example.org", Domains: []string{"renew.example.org"}, TOSAgreed: true, AutoRenew: true, RenewBeforeDays: 30})
	if e != nil {
		t.Fatal(e)
	}
	j, e := m.Queue(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m.execute(ctx, j)
	first, _, e := m.profile(p.ID)
	if e != nil || first.LatestID == "" {
		t.Fatal(first, e)
	}
	firstEntry, _ := m.get(first.LatestID)
	fallback, _ := tls.X509KeyPair(firstEntry.PEM, firstEntry.Key)
	if e = m.AttachTLS(fallback, func(context.Context, *tls.Certificate, string) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = m.SwitchTLS(ctx, first.LatestID, "renew.example.org", 30); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfirmTLS(first.LatestID, "renew.example.org"); e != nil {
		t.Fatal(e)
	}
	j, e = m.Queue(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	m.execute(ctx, j)
	second, _, _ := m.profile(p.ID)
	if second.LatestID == first.LatestID {
		t.Fatal("renewal overwrote immutable version")
	}
	m.maintenance(ctx)
	if m.TLSStatus().ActiveID != second.LatestID {
		t.Fatal("renewed certificate not deployed to assigned panel")
	}
	previous, _ := m.get(first.LatestID)
	if previous.Fingerprint == "" {
		t.Fatal("old version lost")
	}
	m.HTTPClient = rejectHTTP{}
	j, e = m.Queue(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	m.execute(ctx, j)
	failed, _, _ := m.profile(p.ID)
	jobs, _ := m.Jobs()
	if failed.LatestID != second.LatestID || jobs[0].Status != "queued" || jobs[0].Error == "" || !jobs[0].RetryAt.After(m.now()) {
		t.Fatal("renewal failure lost certificate/backoff", failed, jobs)
	}
}

type rejectHTTP struct{}

func (rejectHTTP) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("test CA unavailable")
}

func TestTLSProbeFailureReturnsPrevious(t *testing.T) {
	m := testVault(t)
	ca := testCA(t, m)
	a := testLeaf(t, m, ca, "a.example")
	b := testLeaf(t, m, ca, "b.example")
	x, _ := m.get(a.ID)
	fallback, _ := tls.X509KeyPair(x.PEM, x.Key)
	if e := m.AttachTLS(fallback, func(context.Context, *tls.Certificate, string) error { return errors.New("listener unavailable") }); e != nil {
		t.Fatal(e)
	}
	if _, e := m.SwitchTLS(context.Background(), b.ID, "b.example", 30); e == nil {
		t.Fatal("broken probe accepted")
	}
	pair, _ := m.GetCertificate(nil)
	if m.TLSStatus().PendingID != "" || fingerprint(pair.Certificate[0]) != a.Fingerprint {
		t.Fatal("failed activation did not restore fallback")
	}
}
