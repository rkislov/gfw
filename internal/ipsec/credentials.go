package ipsec

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/gfw/internal/vpncred"
)

type Material struct {
	Tunnel      Tunnel `json:"tunnel"`
	CAID        string `json:"ca_id"`
	CA          []byte `json:"ca"`
	CRL         []byte `json:"crl"`
	Certificate []byte `json:"certificate"`
	Key         []byte `json:"key"`
	Peer        []byte `json:"peer"`
}

func ref(t Tunnel) string {
	raw, _ := json.Marshal(t)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]) + ".bundle"
}

func ValidateMaterial(b Material) error {
	if e := ValidateTunnel(b.Tunnel); e != nil {
		return e
	}
	if !vpncred.SafePEM(b.Certificate, "CERTIFICATE") || !vpncred.SafePEM(b.Key, "PRIVATE KEY") || (b.Tunnel.Auth == nil || b.Tunnel.Auth.Certificate) && !vpncred.SafePEM(b.Peer, "CERTIFICATE") {
		return errors.New("недопустимый PEM")
	}
	if _, e := tls.X509KeyPair(b.Certificate, b.Key); e != nil {
		return e
	}
	return checkCertificates(b, vpncred.CRLUpdate{CAID: b.CAID, CA: b.CA, CRL: b.CRL})
}

func checkCertificates(b Material, update vpncred.CRLUpdate) error {
	if b.CAID != update.CAID || !bytes.Equal(b.CA, update.CA) {
		return errors.New("издатель CRL не совпадает")
	}
	ca, e := vpncred.Leaf(b.CA)
	if e != nil {
		return e
	}
	list, e := vpncred.ParseCRL(update)
	if e != nil {
		return e
	}
	now := time.Now()
	if !list.NextUpdate.After(now) || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return errors.New("истёк срок CA или CRL")
	}
	if b.Tunnel.Auth != nil {
		leaf, e := vpncred.Leaf(b.Certificate)
		if e != nil {
			return e
		}
		if e = leaf.VerifyHostname(b.Tunnel.PublicEndpoint); e != nil {
			return fmt.Errorf("сертификат IKEv2 не подтверждает публичный адрес: %w", e)
		}
	}
	certs := [][]byte{b.Certificate}
	if b.Tunnel.Auth == nil || b.Tunnel.Auth.Certificate {
		certs = append(certs, b.Peer)
	}
	for _, raw := range certs {
		c, e := vpncred.Leaf(raw)
		if e != nil {
			return e
		}
		if c.IsCA || c.CheckSignatureFrom(ca) != nil || !vpncred.UsableCert(c, list) {
			return errors.New("сертификат шлюза отозван, просрочен или выпущен другим CA")
		}
	}
	if len(certs) == 1 {
		return nil
	}
	own, _ := vpncred.Leaf(b.Certificate)
	peer, _ := vpncred.Leaf(b.Peer)
	if b.Tunnel.Auth != nil {
		if err := peer.VerifyHostname(b.Tunnel.ClientUser); err != nil {
			return errors.New("DNS SAN сертификата клиента IKEv2 должен совпадать с логином")
		}
	}
	if bytes.Equal(own.Raw, peer.Raw) {
		return fmt.Errorf("сертификаты шлюзов должны различаться")
	}
	return nil
}
