package openvpn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeFixture(t *testing.T) (Material, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(der)
	makeLeaf := func(role x509.ExtKeyUsage, serial int64) ([]byte, []byte) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "client"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}}
		raw, e := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		secret, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret})
	}
	cert, key := makeLeaf(x509.ExtKeyUsageServerAuth, 2)
	peer, _ := makeLeaf(x509.ExtKeyUsageClientAuth, 3)
	instance := Instance{ID: strings.Repeat("1", 32), Name: "Server", Interface: "ovpn0", Mode: "server", Enabled: true, CertificateID: strings.Repeat("2", 32), Address: "10.80.0.1/24", BindAddress: "192.0.2.1", Protocol: "udp", Port: 1194, Clients: []Client{{CertificateID: strings.Repeat("3", 32), Address: "10.80.0.2"}}}
	raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(6 * time.Hour)}, ca, caKey)
	if e != nil {
		t.Fatal(e)
	}
	return Material{Instance: instance, CAID: strings.Repeat("a", 32), CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Certificate: cert, Key: key, Peers: map[string][]byte{instance.Clients[0].CertificateID: peer}, CRL: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})}, caKey, ca
}
func TestRuntimeVaultAndMonotonicCRL(t *testing.T) {
	b, key, ca := runtimeFixture(t)
	if e := validateMaterial(b); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(t.TempDir(), "vault")
	v, e := OpenVault(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.put(Ref(b.Instance)+".bundle", b); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(root, Ref(b.Instance)+".bundle"))
	if bytes.Contains(raw, b.Key) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext key stored")
	}
	u := CRLUpdate{CAID: b.CAID, CA: b.CA, CRL: b.CRL}
	if _, e = v.SaveCRL(u); e != nil {
		t.Fatal(e)
	}
	next, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(6 * time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: time.Now()}}}, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	if changed, e := v.SaveCRL(CRLUpdate{CAID: b.CAID, CA: b.CA, CRL: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: next})}); e != nil || !changed {
		t.Fatal("new CRL rejected", e)
	}
	if _, e = v.SaveCRL(u); e == nil {
		t.Fatal("older CRL accepted")
	}
	if why, n := v.blocked(b.Instance); why == "" || n != 2 {
		t.Fatal("own revocation ignored", why, n)
	}
	reopened, e := OpenVault(root)
	if e != nil {
		t.Fatal(e)
	}
	if why, n := reopened.blocked(b.Instance); why == "" || n != 2 {
		t.Fatal("revocation lost on restart")
	}
	if e = os.Remove(filepath.Join(root, "device.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenVault(root); e == nil {
		t.Fatal("missing vault key silently replaced")
	}
}
func TestRuntimeRejectsUnsafeDirectivesAndRoutes(t *testing.T) {
	b, _, _ := runtimeFixture(t)
	bad := b
	bad.CA = append(append([]byte{}, b.CA...), []byte("</ca>\nplugin /tmp/evil.so\n<ca>")...)
	if validateMaterial(bad) == nil {
		t.Fatal("PEM directive injection accepted")
	}
	for _, change := range []func(*Instance){func(i *Instance) { i.Interface = "lan0\nup /bin/sh" }, func(i *Instance) { i.Clients[0].Address = "10.80.0.1" }, func(i *Instance) { i.Address = "127.0.0.1/24" }, func(i *Instance) {
		i.Mode = "client"
		i.Clients = nil
		i.BindAddress = ""
		i.ServerCertificateID = strings.Repeat("4", 32)
		i.Remote = "10.80.0.10"
	}, func(i *Instance) { i.Routes = []string{"0.0.0.0/0"} }} {
		i := b.Instance
		i.Clients = append([]Client{}, i.Clients...)
		change(&i)
		if ValidateInstance(i) == nil {
			t.Fatal("unsafe instance accepted", i)
		}
	}
}
func TestManagementSessionParser(t *testing.T) {
	raw := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tUsername\nCLIENT_LIST\talice\t198.51.100.2:12345\t10.80.0.2\t1234\t5678\tlocal-alice\nEND\n"
	rows := parseSessions(raw)
	if len(rows) != 1 || rows[0].Name != "alice" || rows[0].Username != "local-alice" || rows[0].RXBytes != 1234 || rows[0].TXBytes != 5678 {
		t.Fatal(rows)
	}
}
