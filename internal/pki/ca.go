package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type CARequest struct {
	Name       string `json:"name"`
	CommonName string `json:"common_name"`
	Days       int    `json:"days"`
}
type IssueRequest struct {
	Name       string   `json:"name"`
	CAID       string   `json:"ca_id"`
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names"`
	IPs        []string `json:"ips"`
	Usage      string   `json:"usage"`
	Days       int      `json:"days"`
}
type ImportRequest struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validDNS(s string, wildcard bool) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if wildcard && strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if len(s) > 253 || s == "" || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func names(dns []string, ips []string) ([]string, []net.IP, error) {
	if len(dns)+len(ips) > 64 {
		return nil, nil, errors.New("не более 64 SAN")
	}
	out := []string{}
	addresses := []net.IP{}
	seen := map[string]bool{}
	for _, s := range dns {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if !validDNS(s, true) {
			return nil, nil, fmt.Errorf("некорректное DNS-имя %q", s)
		}
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	for _, s := range ips {
		a, e := netip.ParseAddr(s)
		if e != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
			return nil, nil, errors.New("некорректный IP SAN")
		}
		if !seen[a.String()] {
			addresses = append(addresses, net.IP(a.AsSlice()))
			seen[a.String()] = true
		}
	}
	return out, addresses, nil
}
func keyMaterial() (*ecdsa.PrivateKey, []byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), e
}
func serial() (*big.Int, error) {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if n != nil {
		n.Add(n, big.NewInt(1))
	}
	return n, e
}
func certificateEntry(name, kind, ca, usage string, cert, key []byte, now time.Time) (entry, error) {
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return entry{}, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return entry{}, e
	}
	ips := []string{}
	for _, a := range leaf.IPAddresses {
		ips = append(ips, a.String())
	}
	return entry{Certificate: Certificate{ID: id(), Name: name, Kind: kind, CAID: ca, Usage: usage, DNSNames: append([]string{}, leaf.DNSNames...), IPs: ips, Serial: leaf.SerialNumber.Text(16), Fingerprint: fingerprint(leaf.Raw), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), CreatedAt: now.UTC()}, PEM: cert, Key: key}, nil
}
func validTitle(s string) bool {
	return len(strings.TrimSpace(s)) > 0 && len(s) <= 200 && !strings.ContainsAny(s, "\x00\r\n")
}
func (m *Manager) CreateCA(r CARequest) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTitle(r.Name) || !validTitle(r.CommonName) || r.Days < 1 || r.Days > 3650 {
		return Certificate{}, errors.New("нужны имя CA, Common Name и срок 1–3650 дней")
	}
	key, keyPEM, e := keyMaterial()
	if e != nil {
		return Certificate{}, e
	}
	n, e := serial()
	if e != nil {
		return Certificate{}, e
	}
	now := m.now().UTC()
	tpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: r.CommonName, Organization: []string{"GFW"}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Duration(r.Days) * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		return Certificate{}, e
	}
	record, e := certificateEntry(r.Name, "ca", "", "ca", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, now)
	if e != nil {
		return Certificate{}, e
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return Certificate{}, e
	}
	record.CRLNumber = 1
	record.CRL, e = createCRL(ca, key, nil, 1, now)
	if e != nil {
		return Certificate{}, e
	}
	tx, e := m.db.Begin()
	if e != nil {
		return Certificate{}, e
	}
	defer tx.Rollback()
	if e = m.insert(tx, record); e == nil {
		e = audit(tx, "pki.ca.create", record.ID, now)
	}
	if e == nil {
		e = tx.Commit()
	}
	return record.Certificate, e
}
func parseCA(x entry) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	pair, e := tls.X509KeyPair(x.PEM, x.Key)
	if e != nil {
		return nil, nil, e
	}
	ca, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, nil, e
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("неподходящий локальный CA")
	}
	return ca, key, nil
}
func (m *Manager) Issue(r IssueRequest) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTitle(r.Name) || !validTitle(r.CommonName) || r.Days < 1 || r.Days > 397 || (r.Usage != "server" && r.Usage != "client") {
		return Certificate{}, errors.New("нужны имя, Common Name, назначение server/client и срок 1–397 дней")
	}
	dns, ips, e := names(r.DNSNames, r.IPs)
	if e != nil {
		return Certificate{}, e
	}
	if r.Usage == "server" && len(dns)+len(ips) == 0 {
		return Certificate{}, errors.New("серверному сертификату нужен SAN DNS/IP")
	}
	root, e := m.get(r.CAID)
	if e != nil {
		return Certificate{}, e
	}
	if root.Kind != "ca" {
		return Certificate{}, errors.New("выберите локальный CA")
	}
	ca, signer, e := parseCA(root)
	if e != nil {
		return Certificate{}, e
	}
	now := m.now().UTC()
	expiry := now.Add(time.Duration(r.Days) * 24 * time.Hour)
	if now.Before(ca.NotBefore) || expiry.After(ca.NotAfter) {
		return Certificate{}, errors.New("срок сертификата выходит за срок действия CA")
	}
	key, keyPEM, e := keyMaterial()
	if e != nil {
		return Certificate{}, e
	}
	n, e := serial()
	if e != nil {
		return Certificate{}, e
	}
	eku := x509.ExtKeyUsageServerAuth
	if r.Usage == "client" {
		eku = x509.ExtKeyUsageClientAuth
	}
	tpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: r.CommonName}, DNSNames: dns, IPAddresses: ips, NotBefore: now.Add(-5 * time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, signer)
	if e != nil {
		return Certificate{}, e
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), root.PEM...)
	record, e := certificateEntry(r.Name, "local", root.ID, r.Usage, chain, keyPEM, now)
	if e != nil {
		return Certificate{}, e
	}
	tx, e := m.db.Begin()
	if e != nil {
		return Certificate{}, e
	}
	defer tx.Rollback()
	if e = m.insert(tx, record); e == nil {
		e = audit(tx, "pki.certificate.issue", record.ID, now)
	}
	if e == nil {
		e = tx.Commit()
	}
	return record.Certificate, e
}
func validatePair(cert, key []byte, now time.Time) (*tls.Certificate, error) {
	if len(cert) > 1<<20 || len(key) > 64<<10 {
		return nil, errors.New("PEM exceeds size limit")
	}
	rest := bytes.TrimSpace(cert)
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("цепочка PEM должна содержать только CERTIFICATE, без закрытых ключей и посторонних данных")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, errors.New("неверный CERTIFICATE PEM")
		}
		count++
		if count > 8 {
			return nil, errors.New("цепочка слишком длинная")
		}
		rest = bytes.TrimSpace(next)
	}

	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return nil, errors.New("слабый алгоритм подписи сертификата")
	}
	if leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("нужен действующий конечный сертификат, не CA")
	}
	if leaf.PublicKeyAlgorithm == x509.RSA {
		if leaf.PublicKey.(*rsa.PublicKey).N.BitLen() < 2048 {
			return nil, errors.New("RSA-ключ должен быть не короче 2048 бит")
		}
	} else if leaf.PublicKeyAlgorithm == x509.ECDSA && leaf.PublicKey.(*ecdsa.PublicKey).Curve.Params().BitSize < 256 {
		return nil, errors.New("ECDSA-ключ должен быть не короче 256 бит")
	} else if leaf.PublicKeyAlgorithm != x509.ECDSA && leaf.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, errors.New("неподдерживаемый алгоритм ключа")
	}
	for i := 0; i+1 < len(pair.Certificate); i++ {
		child, e := x509.ParseCertificate(pair.Certificate[i])
		if e != nil {
			return nil, e
		}
		parent, e := x509.ParseCertificate(pair.Certificate[i+1])
		if e != nil {
			return nil, e
		}
		if e = child.CheckSignatureFrom(parent); e != nil {
			return nil, fmt.Errorf("неверный порядок/подпись цепочки: %w", e)
		}
		if now.Before(parent.NotBefore) || !now.Before(parent.NotAfter) {
			return nil, errors.New("просроченный издатель в цепочке")
		}
	}
	pair.Leaf = leaf
	return &pair, nil
}
func (m *Manager) Import(r ImportRequest) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTitle(r.Name) || len(r.CertificatePEM) > 1<<20 || len(r.PrivateKeyPEM) > 64<<10 {
		return Certificate{}, errors.New("неверное имя или слишком большой PEM")
	}
	if _, e := validatePair([]byte(r.CertificatePEM), []byte(r.PrivateKeyPEM), m.now()); e != nil {
		return Certificate{}, e
	}
	record, e := certificateEntry(r.Name, "imported", "", "external", []byte(r.CertificatePEM), []byte(r.PrivateKeyPEM), m.now())
	if e != nil {
		return Certificate{}, e
	}
	tx, e := m.db.Begin()
	if e != nil {
		return Certificate{}, e
	}
	defer tx.Rollback()
	if e = m.insert(tx, record); e == nil {
		e = audit(tx, "pki.certificate.import", record.ID, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	return record.Certificate, e
}
func createCRL(ca *x509.Certificate, key *ecdsa.PrivateKey, revoked []x509.RevocationListEntry, number int64, now time.Time) ([]byte, error) {
	next := now.Add(7 * 24 * time.Hour)
	if next.After(ca.NotAfter) {
		next = ca.NotAfter
	}
	if !next.After(now) {
		return nil, errors.New("CA истёк")
	}
	raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now, NextUpdate: next, RevokedCertificateEntries: revoked}, ca, key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw}), nil
}
func (m *Manager) Revoke(id string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, e := m.get(id)
	if e != nil {
		return Certificate{}, e
	}
	if x.Kind != "local" {
		return Certificate{}, errors.New("отзыв здесь доступен для сертификатов локального CA")
	}
	if x.RevokedAt != nil {
		return x.Certificate, nil
	}
	var active, pending string
	if e = m.db.QueryRow("SELECT active_id,pending_id FROM panel_tls WHERE id=1").Scan(&active, &pending); e != nil {
		return Certificate{}, e
	}
	if active == id || pending == id {
		return Certificate{}, errors.New("сначала смените сертификат панели")
	}
	root, e := m.get(x.CAID)
	if e != nil {
		return Certificate{}, e
	}
	ca, key, e := parseCA(root)
	if e != nil {
		return Certificate{}, e
	}
	rows, e := m.db.Query("SELECT meta FROM certificates WHERE json_extract(meta,'$.ca_id')=?", root.ID)
	if e != nil {
		return Certificate{}, e
	}
	all := []Certificate{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return Certificate{}, e
		}
		var c Certificate
		if e = json.Unmarshal([]byte(raw), &c); e != nil {
			rows.Close()
			return Certificate{}, e
		}
		all = append(all, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Certificate{}, e
	}
	now := m.now().UTC()
	revoked := []x509.RevocationListEntry{}
	for _, cert := range all {
		if cert.CAID != root.ID {
			continue
		}
		when := cert.RevokedAt
		if cert.ID == id {
			when = &now
		}
		if when != nil {
			n, ok := new(big.Int).SetString(cert.Serial, 16)
			if !ok {
				return Certificate{}, errors.New("invalid stored serial")
			}
			revoked = append(revoked, x509.RevocationListEntry{SerialNumber: n, RevocationTime: *when, ReasonCode: 0})
		}
	}
	crl, e := createCRL(ca, key, revoked, root.CRLNumber+1, now)
	if e != nil {
		return Certificate{}, e
	}
	x.RevokedAt = &now
	body, _ := json.Marshal(x.Certificate)
	tx, e := m.db.Begin()
	if e != nil {
		return Certificate{}, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE certificates SET meta=? WHERE id=?", string(body), id); e == nil {
		_, e = tx.Exec("UPDATE certificates SET crl=?,crl_number=crl_number+1 WHERE id=?", crl, root.ID)
	}
	if e == nil {
		e = audit(tx, "pki.certificate.revoke", id, now)
	}
	if e == nil {
		e = tx.Commit()
	}
	return x.Certificate, e
}
func (m *Manager) CRL(id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.crlLocked(id)
}
func (m *Manager) crlLocked(id string) ([]byte, error) {
	root, e := m.get(id)
	if e != nil {
		return nil, e
	}
	if root.Kind != "ca" {
		return nil, sql.ErrNoRows
	}
	block, _ := pem.Decode(root.CRL)
	if block != nil {
		parsed, err := x509.ParseRevocationList(block.Bytes)
		if err == nil && parsed.NextUpdate.After(m.now().Add(24*time.Hour)) {
			return root.CRL, nil
		}
	}
	ca, key, e := parseCA(root)
	if e != nil {
		return nil, e
	}
	rows, e := m.db.Query("SELECT meta FROM certificates WHERE json_extract(meta,'$.ca_id')=?", id)
	if e != nil {
		return nil, e
	}
	revoked := []x509.RevocationListEntry{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return nil, e
		}
		var c Certificate
		if e = json.Unmarshal([]byte(raw), &c); e != nil {
			rows.Close()
			return nil, e
		}
		if c.RevokedAt != nil {
			n, ok := new(big.Int).SetString(c.Serial, 16)
			if !ok {
				rows.Close()
				return nil, errors.New("invalid stored serial")
			}
			revoked = append(revoked, x509.RevocationListEntry{SerialNumber: n, RevocationTime: *c.RevokedAt, ReasonCode: 0})
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	raw, e := createCRL(ca, key, revoked, root.CRLNumber+1, m.now().UTC())
	if e != nil {
		return nil, e
	}
	tx, e := m.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE certificates SET crl=?,crl_number=crl_number+1 WHERE id=?", raw, id); e == nil {
		e = audit(tx, "pki.crl.refresh", id, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	return raw, e
}
