package openvpn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/rkislov/gfw/internal/vpncred"
	"regexp"
	"time"
)

var regexpCN = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}$`)

func validateMaterial(b Material) error {
	if !vpncred.SafePEM(b.CA, "CERTIFICATE") || !vpncred.SafePEM(b.Certificate, "CERTIFICATE") || !vpncred.SafePEM(b.Key, "PRIVATE KEY") {
		return errors.New("unsafe OpenVPN PEM")
	}
	for _, raw := range b.Peers {
		if !vpncred.SafePEM(raw, "CERTIFICATE") {
			return errors.New("unsafe peer PEM")
		}
	}

	if e := ValidateInstance(b.Instance); e != nil {
		return e
	}
	if !IDPattern.MatchString(b.CAID) {
		return errors.New("invalid issuer reference")
	}
	ca, e := vpncred.Leaf(b.CA)
	if e != nil {
		return e
	}
	if !ca.IsCA {
		return errors.New("issuer must be CA")
	}
	pair, e := tls.X509KeyPair(b.Certificate, b.Key)
	if e != nil {
		return e
	}
	c, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return e
	}
	if e = c.CheckSignatureFrom(ca); e != nil {
		return e
	}
	expected := x509.ExtKeyUsageServerAuth
	if b.Instance.Mode == "client" {
		expected = x509.ExtKeyUsageClientAuth
	}
	if !hasUsage(c, expected) || c.IsCA {
		return errors.New("wrong OpenVPN certificate role")
	}
	ids := map[string]bool{}
	if b.Instance.Mode == "client" {
		ids[b.Instance.ServerCertificateID] = true
	} else {
		for _, p := range b.Instance.Clients {
			if p.CertificateID != "" {
				ids[p.CertificateID] = true
			}
		}
	}
	if len(ids) != len(b.Peers) {
		return errors.New("peer certificate set mismatch")
	}
	seenCN := map[string]bool{}
	for id, raw := range b.Peers {
		if !ids[id] {
			return errors.New("unexpected peer")
		}
		p, e := vpncred.Leaf(raw)
		if e != nil {
			return e
		}
		if e = p.CheckSignatureFrom(ca); e != nil {
			return e
		}
		usage := x509.ExtKeyUsageClientAuth
		if b.Instance.Mode == "client" {
			usage = x509.ExtKeyUsageServerAuth
		}
		if b.Instance.Mode == "server" {
			cn := p.Subject.CommonName
			if !regexpCN.MatchString(cn) || cn == "DEFAULT" || seenCN[cn] {
				return errors.New("client CN must be safe and unique")
			}
			seenCN[cn] = true
			for _, client := range b.Instance.Clients {
				if client.CertificateID == id && client.Username != "" && client.Username != cn {
					return errors.New("CN сертификата клиента должен совпадать с его логином")
				}
			}
		}
		if !hasUsage(p, usage) || p.IsCA {
			return errors.New("wrong peer role")
		}
	}
	_, e = vpncred.ParseCRL(CRLUpdate{CAID: b.CAID, CA: b.CA, CRL: b.CRL})
	return e
}
func hasUsage(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, v := range c.ExtKeyUsage {
		if v == u {
			return true
		}
	}
	return false
}
func (v *Vault) blocked(i Instance) (string, int64) {
	b, e := v.Material(i)
	if e != nil {
		return "ключи экземпляра недоступны", 0
	}
	u, e := v.CRL(b.CAID)
	if e != nil {
		return "CRL недоступен", 0
	}
	r, e := vpncred.ParseCRL(u)
	if e != nil {
		return "CRL повреждён", 0
	}
	n := r.Number.Int64()
	if !r.NextUpdate.After(time.Now()) {
		return "срок CRL истёк", n
	}
	c, e := vpncred.Leaf(b.Certificate)
	if e != nil || !vpncred.UsableCert(c, r) {
		return "сертификат экземпляра отозван или истёк", n
	}
	ca, e := vpncred.Leaf(b.CA)
	if e != nil || time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return "CA недействителен", n
	}
	if i.Mode == "client" {
		peer, e := vpncred.Leaf(b.Peers[i.ServerCertificateID])
		if e != nil || !vpncred.UsableCert(peer, r) {
			return "сертификат удалённого сервера отозван или истёк", n
		}
	}
	return "", n
}
