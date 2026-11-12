package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/openvpn"
)

func vpnFixture(t *testing.T, m *Manager) (openvpn.Profile, Certificate, Certificate, Certificate) {
	t.Helper()
	ca := testCA(t, m)
	server := testLeaf(t, m, ca, "vpn.home.arpa")
	client, e := m.Issue(IssueRequest{Name: "Alice", CommonName: "alice", CAID: ca.ID, Usage: "client", Days: 20})
	if e != nil {
		t.Fatal(e)
	}
	return openvpn.Profile{ID: strings.Repeat("4", 32), Name: "Office", Remote: "vpn.home.arpa", Port: 1194, Protocol: "udp", ServerCertificateID: server.ID, ClientCertificateID: client.ID, Routes: []string{"10.50.0.0/24"}, DNS: []string{}}, ca, server, client
}
func inline(t *testing.T, s, tag string) []byte {
	t.Helper()
	a, b := "<"+tag+">\n", "\n</"+tag+">"
	_, rest, ok := strings.Cut(s, a)
	if !ok {
		t.Fatal("block missing", tag)
	}
	raw, _, ok := strings.Cut(rest, b)
	if !ok {
		t.Fatal("block not closed", tag)
	}
	return []byte(raw + "\n")
}
func TestOpenVPNExportOnlyClientKeyAndAudited(t *testing.T) {
	m := testVault(t)
	p, ca, server, client := vpnFixture(t, m)
	raw, e := m.ExportOpenVPN(p)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(inline(t, raw, "cert"), inline(t, raw, "key"))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	if fingerprint(leaf.Raw) != client.Fingerprint || len(pair.Certificate) != 1 {
		t.Fatal("wrong client exported")
	}
	for _, id := range []string{ca.ID, server.ID} {
		x, e := m.get(id)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains([]byte(raw), bytes.TrimSpace(x.Key)) {
			t.Fatal("server/CA key leaked")
		}
	}
	block, _ := pem.Decode(inline(t, raw, "ca"))
	root, e := x509.ParseCertificate(block.Bytes)
	if e != nil || fingerprint(root.Raw) != ca.Fingerprint {
		t.Fatal("wrong CA")
	}
	events, e := m.Audit()
	if e != nil {
		t.Fatal(e)
	}
	if events[0]["action"] != "pki.openvpn.client.private_export" {
		t.Fatal("export not audited")
	}
	// Never allow key extraction by selecting a server or CA as the client.
	for _, id := range []string{ca.ID, server.ID} {
		bad := p
		bad.ClientCertificateID = id
		if _, e = m.ExportOpenVPN(bad); e == nil {
			t.Fatal("non-client private key exported")
		}
	}
}
func TestOpenVPNRevalidatesRevocationExpiryAndIssuer(t *testing.T) {
	m := testVault(t)
	p, _, server, client := vpnFixture(t, m)
	otherCA := testCA(t, m)
	otherServer := testLeaf(t, m, otherCA, "other.home.arpa")
	bad := p
	bad.ServerCertificateID = otherServer.ID
	if _, e := m.ExportOpenVPN(bad); e == nil {
		t.Fatal("mixed issuer accepted")
	}
	if _, e := m.Revoke(client.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := m.ExportOpenVPN(p); e == nil {
		t.Fatal("revoked client exported")
	}
	p, _, _, _ = vpnFixture(t, m)
	if _, e := m.Revoke(p.ServerCertificateID); e != nil {
		t.Fatal(e)
	}
	if _, e := m.ExportOpenVPN(p); e == nil {
		t.Fatal("revoked server accepted")
	}
	p, _, _, _ = vpnFixture(t, m)
	m.now = func() time.Time { return server.NotAfter.Add(24 * time.Hour) }
	if _, e := m.ExportOpenVPN(p); e == nil {
		t.Fatal("expired certificate exported")
	}
}
func TestOpenVPNAuditFailureReturnsNoKey(t *testing.T) {
	m := testVault(t)
	p, _, _, _ := vpnFixture(t, m)
	if _, e := m.db.Exec("CREATE TRIGGER deny_export BEFORE INSERT ON vault_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	raw, e := m.ExportOpenVPN(p)
	if e == nil || raw != "" {
		t.Fatal("private profile returned without durable audit")
	}
}
