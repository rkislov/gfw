package vpncred

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"time"
)

var IDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type CRLUpdate struct {
	CAID string `json:"ca_id"`
	CA   []byte `json:"ca"`
	CRL  []byte `json:"crl"`
}

func Leaf(raw []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}
func ParseCRL(u CRLUpdate) (*x509.RevocationList, error) {
	if !SafePEM(u.CA, "CERTIFICATE") || !SafePEM(u.CRL, "X509 CRL") {
		return nil, errors.New("unsafe CRL PEM")
	}
	if !IDPattern.MatchString(u.CAID) {
		return nil, errors.New("invalid CA ID")
	}
	ca, e := Leaf(u.CA)
	if e != nil {
		return nil, e
	}
	b, _ := pem.Decode(u.CRL)
	if b == nil || b.Type != "X509 CRL" {
		return nil, errors.New("invalid CRL")
	}
	r, e := x509.ParseRevocationList(b.Bytes)
	if e != nil {
		return nil, e
	}
	if e = r.CheckSignatureFrom(ca); e != nil {
		return nil, e
	}
	if r.Number == nil || !r.Number.IsInt64() || r.Number.Sign() < 1 || r.ThisUpdate.After(time.Now().Add(time.Minute)) || !r.NextUpdate.After(r.ThisUpdate) {
		return nil, errors.New("invalid CRL number or lifetime")
	}
	return r, nil
}
func (v *Vault) SaveCRL(u CRLUpdate) (bool, error) {
	r, e := ParseCRL(u)
	if e != nil {
		return false, e
	}
	if !r.NextUpdate.After(time.Now()) {
		return false, errors.New("expired CRL")
	}
	old, e := v.CRL(u.CAID)
	if e == nil {
		previous, e := ParseCRL(old)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(old.CA, u.CA) || r.Number.Cmp(previous.Number) < 0 {
			return false, errors.New("CRL downgrade or changed CA rejected")
		}
		if r.Number.Cmp(previous.Number) == 0 {
			if !bytes.Equal(r.Raw, previous.Raw) {
				return false, errors.New("CRL changed without increasing number")
			}
			return false, nil
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	return true, v.Put(u.CAID+".crl", u)
}
func SafePEM(raw []byte, kind string) bool {
	rest := bytes.TrimSpace(raw)
	count := 0
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN "+kind+"-----")) {
			return false
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != kind || len(block.Headers) > 0 {
			return false
		}
		rest = bytes.TrimSpace(next)
		count++
	}
	return count > 0 && count <= 8
}
func UsableCert(c *x509.Certificate, r *x509.RevocationList) bool {
	now := time.Now()
	if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
		return false
	}
	for _, v := range r.RevokedCertificateEntries {
		if v.SerialNumber.Cmp(c.SerialNumber) == 0 {
			return false
		}
	}
	return true
}
func (v *Vault) CRL(id string) (CRLUpdate, error) {
	var c CRLUpdate
	if !IDPattern.MatchString(id) {
		return c, errors.New("invalid CA ID")
	}
	e := v.Get(id+".crl", &c)
	return c, e
}
