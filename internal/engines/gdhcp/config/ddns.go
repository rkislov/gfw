// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var kerberosPrincipal = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*@[a-zA-Z0-9.-]+$`)

func DNSName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 230 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func (d DDNS) Zones() []string {
	out := append([]string{}, d.ReverseZones...)
	if d.ReverseZone != "" {
		out = append(out, d.ReverseZone)
	}
	return out
}
func ValidateDDNS(d DDNS) error {
	if !d.Enabled {
		return nil
	}
	if !DNSName(d.Zone) || !strings.Contains(strings.TrimSuffix(d.Zone, "."), ".") {
		return fmt.Errorf("ddns.zone must be a DNS domain")
	}
	if !DNSName(d.Server) {
		if ip, e := netip.ParseAddr(d.Server); e != nil || !ip.IsValid() {
			return fmt.Errorf("ddns.server must be a hostname or IP without port")
		}
	}
	if d.Port < 1 || d.Port > 65535 || d.TTL < 1 || d.TTL > 86400 || d.IntervalSeconds < 1 || d.IntervalSeconds > 3600 || d.TimeoutSeconds < 1 || d.TimeoutSeconds > 60 {
		return fmt.Errorf("ddns: invalid port, TTL (1..86400), interval (1..3600) or timeout (1..60)")
	}
	switch d.Auth {
	case "gss-tsig":
		if !kerberosPrincipal.MatchString(d.Principal) || !filepath.IsAbs(d.Keytab) {
			return fmt.Errorf("ddns requires principal user@REALM and an absolute keytab path")
		}
	case "tsig":
		if !filepath.IsAbs(d.KeyFile) {
			return fmt.Errorf("ddns.key_file must be an absolute path for TSIG")
		}
	default:
		return fmt.Errorf("ddns.auth must be gss-tsig or tsig")
	}
	if d.UpdateA != nil && !*d.UpdateA && d.UpdatePTR != nil && !*d.UpdatePTR {
		return fmt.Errorf("ddns: enable A and/or PTR updates")
	}
	for _, name := range d.ProtectedNames {
		if !DNSName(name) {
			return fmt.Errorf("ddns.protected_names: invalid DNS name")
		}
	}
	if (d.UpdatePTR == nil || *d.UpdatePTR) && len(d.Zones()) == 0 {
		return fmt.Errorf("ddns.reverse_zones is required for PTR updates")
	}
	for _, zone := range d.Zones() {
		zone = strings.TrimSuffix(strings.ToLower(zone), ".")
		if !strings.HasSuffix(zone, ".in-addr.arpa") {
			return fmt.Errorf("ddns: reverse zones must be IPv4 in-addr.arpa zones")
		}
		labels := strings.Split(strings.TrimSuffix(zone, ".in-addr.arpa"), ".")
		if len(labels) < 1 || len(labels) > 3 {
			return fmt.Errorf("ddns: reverse zone must cover an IPv4 /8, /16 or /24")
		}
		for _, l := range labels {
			n, e := strconv.Atoi(l)
			if e != nil || n < 0 || n > 255 || strconv.Itoa(n) != l {
				return fmt.Errorf("ddns: invalid reverse zone")
			}
		}
	}
	return nil
}
