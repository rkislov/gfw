// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dnssec

import (
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	proof "github.com/semihalev/sdns/middleware/resolver/dnssec"
	"strings"
)

// RootAnchors were obtained over authenticated HTTPS from IANA on 2026-11-05.
// Both KSK-2017 and KSK-2024 are retained for the published root rollover.
var RootAnchors = []string{
	". 3600 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". 3600 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

type AutoUpdateConfig struct {
	Enabled      bool `json:"enabled"`
	RefreshHours int  `json:"refresh_hours"`
}

type Config struct {
	AutoUpdate         AutoUpdateConfig `json:"auto_update"`
	TrustAnchors       []string         `json:"trust_anchors"`
	ExemptZones        []string         `json:"exempt_zones"`
	MaxNSEC3Iterations *uint16          `json:"max_nsec3_iterations"`
	TimeoutSeconds     int              `json:"timeout_seconds"`
	IgnoreCD           bool             `json:"ignore_cd"`
}

func DefaultConfig() Config {
	n := uint16(150)
	return Config{AutoUpdate: AutoUpdateConfig{RefreshHours: 24}, TrustAnchors: append([]string{}, RootAnchors...), ExemptZones: []string{}, MaxNSEC3Iterations: &n, TimeoutSeconds: 15}
}
func Normalize(c Config) (Config, error) {
	if c.AutoUpdate.RefreshHours == 0 {
		c.AutoUpdate.RefreshHours = 24
	}
	if c.AutoUpdate.RefreshHours < 1 || c.AutoUpdate.RefreshHours > 360 {
		return c, fmt.Errorf("RFC 5011 refresh interval must be 1..360 hours")
	}
	if len(c.TrustAnchors) == 0 {
		c.TrustAnchors = append([]string{}, RootAnchors...)
	} else {
		c.TrustAnchors = append([]string{}, c.TrustAnchors...)
	}
	c.ExemptZones = append([]string{}, c.ExemptZones...)
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 15
	}
	if c.TimeoutSeconds < 5 || c.TimeoutSeconds > 30 {
		return c, fmt.Errorf("DNSSEC timeout must be 5..30 seconds")
	}
	if c.MaxNSEC3Iterations == nil {
		n := uint16(150)
		c.MaxNSEC3Iterations = &n
	} else {
		n := *c.MaxNSEC3Iterations
		c.MaxNSEC3Iterations = &n
	}
	if *c.MaxNSEC3Iterations > 500 {
		return c, fmt.Errorf("DNSSEC NSEC3 iteration limit must be 0..500")
	}
	if len(c.TrustAnchors) > 64 {
		return c, fmt.Errorf("too many DNSSEC trust anchors")
	}
	hasRoot := false
	for i, line := range c.TrustAnchors {
		rr, err := dns.NewRR(line)
		if err != nil {
			return c, fmt.Errorf("invalid DNSSEC trust anchor: %w", err)
		}
		rr.Header().Name = canonical(rr.Header().Name)
		if rr.Header().Class != dns.ClassINET {
			return c, fmt.Errorf("DNSSEC trust anchor must be IN")
		}
		switch key := rr.(type) {
		case *dns.DS:
			raw, err := hex.DecodeString(key.Digest)
			size := map[uint8]int{dns.SHA1: 20, dns.SHA256: 32, dns.SHA384: 48}[key.DigestType]
			if !proof.IsSupportedDS(key) || err != nil || size == 0 || len(raw) != size {
				return c, fmt.Errorf("unsupported or malformed DNSSEC DS anchor")
			}
		case *dns.DNSKEY:
			if key.Protocol != 3 || key.Flags&dns.ZONE == 0 || key.Flags&128 != 0 || !proof.IsSupportedDNSKEYAlgorithm(key.Algorithm) || key.ToDS(dns.SHA256) == nil {
				return c, fmt.Errorf("unsupported or unusable DNSKEY trust anchor")
			}
		default:
			return c, fmt.Errorf("trust anchors must be DS or DNSKEY records")
		}
		hasRoot = hasRoot || rr.Header().Name == "."
		c.TrustAnchors[i] = rr.String()
	}
	if !hasRoot {
		return c, fmt.Errorf("at least one root trust anchor is required")
	}
	for i, n := range c.ExemptZones {
		n = canonical(n)
		if n == "." || !validName(n) {
			return c, fmt.Errorf("invalid DNSSEC exception %q; root exceptions are forbidden", n)
		}
		c.ExemptZones[i] = n
	}
	return c, nil
}
func (c Config) Exempt(name string) bool {
	for _, zone := range c.ExemptZones {
		if dns.IsSubDomain(zone, canonical(name)) {
			return true
		}
	}
	return false
}
func canonical(n string) string { return dns.CanonicalName(dns.Fqdn(n)) }
func validName(n string) bool {
	_, ok := dns.IsDomainName(n)
	return ok && !strings.ContainsAny(n, " /:@\t\n")
}
