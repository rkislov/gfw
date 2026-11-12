package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type Info struct {
	DNSNames          []string
	Issuer            string
	Serial            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

func ParsePair(certPEM, keyPEM string) (Info, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return Info{}, fmt.Errorf("cert_pem and key_pem are required")
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return Info{}, fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return Info{}, fmt.Errorf("no PEM certificate block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Info{}, fmt.Errorf("parse certificate: %w", err)
	}
	names := append([]string{}, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		found := false
		for _, n := range names {
			if strings.EqualFold(n, leaf.Subject.CommonName) {
				found = true
				break
			}
		}
		if !found {
			names = append([]string{leaf.Subject.CommonName}, names...)
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	return Info{
		DNSNames:          names,
		Issuer:            leaf.Issuer.String(),
		Serial:            leaf.SerialNumber.Text(16),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
	}, nil
}

func GenerateSelfSigned(domains []string, days int) (certPEM, keyPEM string, info Info, err error) {
	names := normalizeDomains(domains)
	if len(names) == 0 {
		return "", "", Info{}, fmt.Errorf("at least one domain is required")
	}
	if days <= 0 {
		days = 365
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", Info{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", Info{}, err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"FESS"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", Info{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", Info{}, err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	info, err = ParsePair(certPEM, keyPEM)
	return certPEM, keyPEM, info, err
}

func EncodeAccountKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func ParseAccountKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM private key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("account key is not ECDSA")
	}
	return ek, nil
}

func EncodeDERChain(ders [][]byte) string {
	var b strings.Builder
	for _, der := range ders {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return b.String()
}

func EncodeECDSAKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func normalizeDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func NormalizeDomains(in []string) []string { return normalizeDomains(in) }
