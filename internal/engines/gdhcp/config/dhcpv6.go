// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

func (d DHCPv6) DUID() ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(d.ServerDUID, ":", ""))
}

func (d DHCPv6) Validate() error {
	if !d.Enabled {
		return nil
	}
	listen, err := netip.ParseAddrPort(d.Listen)
	if err != nil || !listen.Addr().Is6() || listen.Addr().Is4In6() || listen.Port() == 0 {
		return fmt.Errorf("listen requires an IPv6 address and UDP port")
	}
	if d.ServerDUID != "" {
		id, err := d.DUID()
		if err != nil || len(id) < 3 || len(id) > 128 {
			return fmt.Errorf("server_duid requires 3..128 hex bytes")
		}
	}
	if d.Preferred < 3 || d.Valid < d.Preferred {
		return fmt.Errorf("require 3 <= preferred_seconds <= valid_seconds")
	}
	if len(d.Pools) == 0 {
		return fmt.Errorf("configure at least one pool")
	}
	if len(d.DNS) > 8 {
		return fmt.Errorf("at most eight DNS servers")
	}
	for _, s := range d.DNS {
		if !v6Unicast(s) {
			return fmt.Errorf("invalid IPv6 DNS address %q", s)
		}
	}
	direct := map[string]bool{}
	var prefixes []netip.Prefix
	for _, p := range d.Pools {
		prefix, err := netip.ParsePrefix(p.Prefix)
		start, _ := netip.ParseAddr(p.Start)
		end, _ := netip.ParseAddr(p.End)
		if err != nil || prefix != prefix.Masked() || !prefix.Addr().Is6() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().Is4In6() || !start.IsGlobalUnicast() || !end.IsGlobalUnicast() || !prefix.Contains(start) || !prefix.Contains(end) || start.Compare(end) > 0 || start == prefix.Addr() {
			return fmt.Errorf("invalid IPv6 pool %q (%s..%s)", p.Prefix, p.Start, p.End)
		}
		for _, other := range prefixes {
			if prefix.Overlaps(other) {
				return fmt.Errorf("overlapping prefixes %s and %s", prefix, other)
			}
		}
		prefixes = append(prefixes, prefix)
		if p.Interface == "" {
			return fmt.Errorf("pool %s requires an interface", prefix)
		}
		if len(p.Relays) == 0 {
			if !listen.Addr().IsUnspecified() {
				return fmt.Errorf("direct pools require a wildcard [::] listen address for multicast")
			}
			if direct[p.Interface] {
				return fmt.Errorf("multiple direct pools on %s", p.Interface)
			}
			direct[p.Interface] = true
		}
		for _, s := range p.Relays {
			if !v6Unicast(s) {
				return fmt.Errorf("invalid IPv6 relay %q", s)
			}
		}
	}
	return nil
}

func v6Unicast(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Is6() && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.Zone() == ""
}
