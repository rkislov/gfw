// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/rkislov/gfw/internal/engines/gdhcp/relay"
)

// Validate checks the configuration after defaults have been applied.
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, args ...any) {
		errs = append(errs, fmt.Sprintf(f, args...))
	}

	if err := c.DHCPv6.Validate(); err != nil {
		add("dhcpv6: %s", err)
	}
	if c.Server.LeaseDefault <= 0 {
		add("server.lease_default must be positive")
	}
	if c.Server.LeaseMax < c.Server.LeaseDefault {
		add("server.lease_max must be >= lease_default")
	}
	if c.Server.ServerID != "" {
		if ip, err := netip.ParseAddr(c.Server.ServerID); err != nil || !ip.Is4() {
			add("server.server_id must be an IPv4 address")
		}
	}
	switch c.Database.Driver {
	case "sqlite", "postgres":
	default:
		add("database.driver must be sqlite or postgres")
	}
	if c.Database.DSN == "" {
		add("database.dsn is required")
	}
	switch c.Relay.UnknownVLANAction {
	case "ignore", "nak", "default-pool":
	default:
		add("relay.unknown_vlan_action must be ignore, nak, or default-pool")
	}
	if c.Relay.MaxRelayHops < 1 || c.Relay.MaxRelayHops > 16 {
		add("relay.max_relay_hops must be between 1 and 16")
	}
	for _, src := range c.Relay.VLANSourcePriority {
		switch src {
		case relay.SourceLinkSelection, relay.SourceCircuitID, relay.SourceGIAddr, relay.SourceDefaultVLAN:
		default:
			add("unknown vlan source %q", src)
		}
	}
	for _, p := range c.Relay.CircuitIDParsers {
		if _, err := relay.Compile(p.Name, p.Regex, p.VLANGroup); err != nil {
			add("%s", err.Error())
		}
	}
	if c.Relay.DefaultPool != "" && !subnetExists(c.Subnets, c.Relay.DefaultPool) {
		add("relay.default_pool %q does not match a subnet", c.Relay.DefaultPool)
	}

	for _, iface := range c.Server.Interfaces {
		if iface.Name == "" {
			add("server.interfaces.name is required")
		}
		switch iface.Mode {
		case "", "access", "trunk":
		default:
			add("interface %s: mode must be access or trunk", iface.Name)
		}
		if iface.Mode == "trunk" && len(iface.VLANs) == 0 {
			add("interface %s: trunk mode requires vlans", iface.Name)
		}
	}

	vlans := map[int]VLAN{}
	for _, v := range c.VLANs {
		if v.ID < 1 || v.ID > 4094 {
			add("vlan %d: id must be 1..4094", v.ID)
		}
		if _, ok := vlans[v.ID]; ok {
			add("vlan %d: duplicate id", v.ID)
		}
		vlans[v.ID] = v
		if v.Priority < 0 || v.Priority > 7 {
			add("vlan %d: priority must be 0..7", v.ID)
		}
		switch v.Source {
		case "", "local", "relay":
		default:
			add("vlan %d: source must be local or relay", v.ID)
		}
		if v.SubnetRef != "" && !subnetExists(c.Subnets, v.SubnetRef) {
			add("vlan %d: subnet_ref %q not found", v.ID, v.SubnetRef)
		}
		if v.Match != nil && v.Match.LinkSelection != "" {
			if ip, err := netip.ParseAddr(v.Match.LinkSelection); err != nil || !ip.Is4() {
				add("vlan %d: match.link_selection must be IPv4", v.ID)
			}
		}
	}

	subnets := map[string]Subnet{}
	var ranges []interval
	for _, s := range c.Subnets {
		if s.ID == "" {
			add("subnet id is required")
			continue
		}
		if _, ok := subnets[s.ID]; ok {
			add("subnet %s: duplicate id", s.ID)
		}
		subnets[s.ID] = s
		prefix, err := netip.ParsePrefix(s.Network)
		if err != nil || !prefix.Addr().Is4() {
			add("subnet %s: network must be an IPv4 prefix", s.ID)
			continue
		}
		if s.VLAN != nil {
			if *s.VLAN < 1 || *s.VLAN > 4094 {
				add("subnet %s: vlan must be 1..4094", s.ID)
			}
		}
		if s.Gateway != "" {
			gw, err := netip.ParseAddr(s.Gateway)
			if err != nil || !gw.Is4() || !prefix.Contains(gw) {
				add("subnet %s: gateway must be inside the network", s.ID)
			}
		}
		for _, dns := range s.DNS {
			if ip, err := netip.ParseAddr(dns); err != nil || !ip.Is4() {
				add("subnet %s: dns %q is not IPv4", s.ID, dns)
			}
		}
		if s.NextServer != "" {
			if ip, err := netip.ParseAddr(s.NextServer); err != nil || !ip.Is4() {
				add("subnet %s: next_server must be IPv4", s.ID)
			}
		}
		if len(s.Range) != 0 && len(s.Range) != 2 {
			add("subnet %s: range must be [start, end]", s.ID)
			continue
		}
		if len(s.Range) == 2 {
			start, err1 := netip.ParseAddr(s.Range[0])
			end, err2 := netip.ParseAddr(s.Range[1])
			if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() {
				add("subnet %s: range addresses must be IPv4", s.ID)
				continue
			}
			if !prefix.Contains(start) || !prefix.Contains(end) {
				add("subnet %s: range must lie inside the network", s.ID)
			}
			if start.Compare(end) > 0 {
				add("subnet %s: range start is after end", s.ID)
			}
			ranges = append(ranges, interval{id: s.ID, start: ipv4u(start), end: ipv4u(end)})
		}
		if s.Lease > c.Server.LeaseMax {
			add("subnet %s: lease exceeds server.lease_max", s.ID)
		}
	}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].overlaps(ranges[j]) {
				add("subnets %s and %s have overlapping ranges", ranges[i].id, ranges[j].id)
			}
		}
	}

	for _, r := range c.AllReservations() {
		if r.IP == "" {
			add("reservation: ip is required")
			continue
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() {
			add("reservation %s: ip must be IPv4", r.IP)
			continue
		}
		if r.MAC != "" {
			if _, err := net.ParseMAC(r.MAC); err != nil {
				add("reservation %s: mac %q: %v", r.IP, r.MAC, err)
			}
		}
		if r.MAC == "" && r.ClientID == "" {
			add("reservation %s: mac or client_id is required", r.IP)
		}
		sub, ok := subnets[r.SubnetID]
		if r.SubnetID == "" || !ok {
			add("reservation %s: subnet_id %q not found", r.IP, r.SubnetID)
			continue
		}
		prefix, err := netip.ParsePrefix(sub.Network)
		if err == nil && !prefix.Contains(ip) {
			add("reservation %s: ip is outside subnet %s", r.IP, sub.ID)
		}
	}

	seenGI := map[string]struct{}{}
	for _, t := range c.Relay.TrustedRelays {
		if t.GIAddr == "" && t.RemoteID == "" {
			add("trusted relay needs giaddr or remote_id")
			continue
		}
		if t.GIAddr != "" {
			ip, err := netip.ParseAddr(t.GIAddr)
			if err != nil || !ip.Is4() {
				add("trusted relay giaddr %q must be IPv4", t.GIAddr)
			}
			if _, ok := seenGI[t.GIAddr]; ok {
				add("trusted relay giaddr %s is duplicated", t.GIAddr)
			}
			seenGI[t.GIAddr] = struct{}{}
		}
		if t.SubnetID != "" && !subnetExists(c.Subnets, t.SubnetID) {
			add("trusted relay %s: subnet_id not found", t.GIAddr)
		}
	}

	if err := ValidateDDNS(c.DDNS); err != nil {
		add("%s", err)
	}
	if err := ValidateLDAP(c.API.Auth.LDAP); err != nil {
		add("%s", err)
	}
	groups := map[string]struct{}{}
	validScope := func(name string, ids []int) {
		seen := map[int]bool{}
		for _, id := range ids {
			if id < 1 || id > 4094 || seen[id] {
				add("%s: VLAN IDs must be unique and in 1..4094", name)
			}
			seen[id] = true
		}
	}
	for _, g := range c.API.Auth.Groups {
		if g.Name == "" {
			add("access group name is required")
		}
		if _, ok := groups[g.Name]; ok {
			add("duplicate access group %s", g.Name)
		}
		groups[g.Name] = struct{}{}
		if g.Role != "admin" && g.Role != "operator" && g.Role != "viewer" {
			add("group %s: invalid role", g.Name)
		}
		validScope(g.Name, g.VLANIDs)
		if err := validateGroupDN(g.LDAPDN); err != nil {
			add("group %s: %s", g.Name, err)
		}
	}
	roles := map[string]struct{}{"admin": {}, "operator": {}, "viewer": {}}
	users := map[string]struct{}{}
	for _, u := range c.API.Auth.Users {
		validScope(u.Username, u.VLANIDs)
		for _, name := range u.Groups {
			if _, ok := groups[name]; !ok {
				add("user %s: unknown access group %s", u.Username, name)
			}
		}
		if u.Username == "" {
			add("api user username is required")
		}
		if _, ok := users[u.Username]; ok {
			add("duplicate api user %s", u.Username)
		}
		users[u.Username] = struct{}{}
		if _, ok := roles[u.Role]; !ok && !(u.Role == "" && len(u.Groups) > 0) {
			add("user %s: role must be admin, operator, or viewer", u.Username)
		}
		if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
			add("user %s: password_hash must be argon2id", u.Username)
		}
	}
	if (len(c.API.Auth.Users) > 0 || c.API.Auth.LDAP.Enabled) && strings.TrimSpace(c.API.Auth.JWTSecret) == "" {
		add("api.auth.jwt_secret is required when users are configured")
	}
	for _, k := range c.API.Auth.APIKeys {
		validScope(k.Name, k.VLANIDs)
		if k.Key == "" || k.Name == "" {
			add("api key name and key are required")
		}
		if _, ok := roles[k.Role]; !ok {
			add("api key %s: invalid role", k.Name)
		}
	}
	for _, class := range c.Classes {
		if class.Subnet != "" && !subnetExists(c.Subnets, class.Subnet) {
			add("class %s: subnet %q not found", class.Name, class.Subnet)
		}
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		add("logging.level must be debug, info, warn, or error")
	}
	switch c.Logging.Format {
	case "json", "text":
	default:
		add("logging.format must be json or text")
	}
	if c.API.TLS.Enabled && (c.API.TLS.Cert == "" || c.API.TLS.Key == "") {
		add("api.tls.cert and api.tls.key are required when tls is enabled")
	}
	if c.HA.Enabled {
		switch c.HA.Role {
		case "primary", "secondary":
		default:
			add("ha.role must be primary or secondary")
		}
		if c.HA.Split < 0 || c.HA.Split > 255 {
			add("ha.split must be 0..255")
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("config: %s", strings.Join(errs, "; "))
}

func subnetExists(subnets []Subnet, id string) bool {
	for _, s := range subnets {
		if s.ID == id {
			return true
		}
	}
	return false
}

type interval struct {
	id         string
	start, end uint32
}

func (a interval) overlaps(b interval) bool {
	return a.start <= b.end && b.start <= a.end
}

func ipv4u(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
