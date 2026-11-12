package acmeissue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/rkislov/gfw/internal/engines/fess/certs"
)

type ChallengePutFunc func(ctx context.Context, domain, token, keyAuth string, ttl time.Duration) error

type Result struct {
	CertPEM string
	KeyPEM  string
	Info    certs.Info
}

func IssueHTTP01(ctx context.Context, client *acme.Client, domains []string, put ChallengePutFunc) (Result, error) {
	var out Result
	names := certs.NormalizeDomains(domains)
	if len(names) == 0 {
		return out, fmt.Errorf("укажите хотя бы одно имя")
	}
	for _, n := range names {
		if strings.HasPrefix(n, "*.") {
			return out, fmt.Errorf("HTTP-01 не выпускает wildcard (%s); используйте загруженный сертификат", n)
		}
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return out, fmt.Errorf("ACME order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		az, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return out, fmt.Errorf("authorization: %w", err)
		}
		if az.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range az.Challenges {
			if c != nil && c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return out, fmt.Errorf("у CA нет HTTP-01 для %s", az.Identifier.Value)
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return out, err
		}
		if err := put(ctx, az.Identifier.Value, chal.Token, keyAuth, 15*time.Minute); err != nil {
			return out, fmt.Errorf("store challenge: %w", err)
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return out, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, az.URI); err != nil {
			return out, fmt.Errorf("wait authorization %s: %w", az.Identifier.Value, err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return out, fmt.Errorf("wait order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return out, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, key)
	if err != nil {
		return out, err
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return out, fmt.Errorf("finalize cert: %w", err)
	}
	keyPEM, err := certs.EncodeECDSAKey(key)
	if err != nil {
		return out, err
	}
	certPEM := certs.EncodeDERChain(ders)
	info, err := certs.ParsePair(certPEM, keyPEM)
	if err != nil {
		return out, err
	}
	out.CertPEM, out.KeyPEM, out.Info = certPEM, keyPEM, info
	return out, nil
}

func NewClient(accountKey *ecdsa.PrivateKey, directoryURL string) *acme.Client {
	dir := strings.TrimSpace(directoryURL)
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	return &acme.Client{Key: accountKey, DirectoryURL: dir}
}
