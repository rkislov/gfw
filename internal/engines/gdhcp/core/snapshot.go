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

package core

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/pool"
	"github.com/rkislov/gfw/internal/engines/gdhcp/relay"
)

// Snapshot is an immutable view of the running configuration.
type Snapshot struct {
	Gen      int64
	Cfg      *config.Config
	Subnets  map[string]*Subnet
	Parsers  []relay.Parser
	Networks []relay.Network
	Routes   []relay.Route
	Pools    []pool.Spec
}

// Subnet is a runtime subnet with parsed addresses.
type Subnet struct {
	ID            string
	Prefix        netip.Prefix
	Start         netip.Addr
	End           netip.Addr
	Gateway       netip.Addr
	DNS           []netip.Addr
	Domain        string
	VLAN          *int
	PCP           int
	Options       map[int]string
	Lease         time.Duration
	T1            time.Duration
	T2            time.Duration
	NextServer    netip.Addr
	BootFile      string
	LinkSelection netip.Addr
	Reservations  []config.Reservation
}

func (s *Subnet) reservation(mac, clientID string) (config.Reservation, bool) {
	for _, r := range s.Reservations {
		if r.MAC != "" && model.NormalizeMAC(r.MAC) == mac {
			return r, true
		}
		if clientID != "" && r.ClientID != "" && r.ClientID == clientID {
			return r, true
		}
	}
	return config.Reservation{}, false
}

func (s *Snapshot) serverID() (netip.Addr, bool) {
	if s == nil || s.Cfg == nil || s.Cfg.Server.ServerID == "" {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(s.Cfg.Server.ServerID)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, false
	}
	return ip, true
}

func (s *Snapshot) byVLAN(id int) *Subnet {
	for _, sub := range s.Subnets {
		if sub.VLAN != nil && *sub.VLAN == id {
			return sub
		}
	}
	return nil
}

func (s *Snapshot) byIP(ip netip.Addr) *Subnet {
	var best *Subnet
	bestBits := -1
	for _, sub := range s.Subnets {
		if sub.Prefix.IsValid() && sub.Prefix.Contains(ip) && sub.Prefix.Bits() > bestBits {
			best = sub
			bestBits = sub.Prefix.Bits()
		}
	}
	return best
}

func (s *Snapshot) defaultSubnet() *Subnet {
	if s.Cfg.Relay.DefaultPool != "" {
		if sub := s.Subnets[s.Cfg.Relay.DefaultPool]; sub != nil {
			return sub
		}
	}
	if s.Cfg.Relay.DefaultVLAN != nil {
		return s.byVLAN(*s.Cfg.Relay.DefaultVLAN)
	}
	return nil
}

func buildSnapshot(cfg *config.Config, gen int64) (*Snapshot, error) {
	snap := &Snapshot{
		Gen:     gen,
		Cfg:     cfg,
		Subnets: map[string]*Subnet{},
	}
	var parsers []relay.Parser
	for _, p := range cfg.Relay.CircuitIDParsers {
		compiled, err := relay.Compile(p.Name, p.Regex, p.VLANGroup)
		if err != nil {
			return nil, err
		}
		parsers = append(parsers, compiled)
	}
	snap.Parsers = relay.MergeParsers(parsers)

	vlanByID := map[int]config.VLAN{}
	for _, v := range cfg.VLANs {
		vlanByID[v.ID] = v
	}

	for _, raw := range cfg.Subnets {
		sub, spec, err := buildSubnet(cfg, raw, vlanByID)
		if err != nil {
			return nil, err
		}
		snap.Subnets[sub.ID] = sub
		snap.Pools = append(snap.Pools, spec)
		netw := relay.Network{ID: sub.ID, VLAN: sub.VLAN, Prefix: sub.Prefix, LinkSelection: sub.LinkSelection}
		snap.Networks = append(snap.Networks, netw)
	}
	for _, t := range cfg.Relay.TrustedRelays {
		snap.Routes = append(snap.Routes, relay.Route{
			GIAddr:   t.GIAddr,
			VLAN:     t.VLAN,
			SubnetID: t.SubnetID,
		})
	}
	return snap, nil
}

func buildSubnet(cfg *config.Config, raw config.Subnet, vlans map[int]config.VLAN) (*Subnet, pool.Spec, error) {
	prefix, err := netip.ParsePrefix(raw.Network)
	if err != nil {
		return nil, pool.Spec{}, fmt.Errorf("subnet %s: %w", raw.ID, err)
	}
	sub := &Subnet{
		ID:       raw.ID,
		Prefix:   prefix,
		Domain:   raw.Domain,
		VLAN:     raw.VLAN,
		Options:  map[int]string{},
		Lease:    raw.Lease,
		T1:       raw.T1,
		T2:       raw.T2,
		BootFile: raw.BootFile,
	}
	if sub.Lease == 0 {
		sub.Lease = cfg.Server.LeaseDefault
	}
	if raw.Gateway != "" {
		sub.Gateway, err = netip.ParseAddr(raw.Gateway)
		if err != nil {
			return nil, pool.Spec{}, err
		}
	}
	for _, d := range raw.DNS {
		ip, err := netip.ParseAddr(d)
		if err != nil {
			return nil, pool.Spec{}, err
		}
		sub.DNS = append(sub.DNS, ip)
	}
	if len(raw.Range) == 2 {
		sub.Start, err = netip.ParseAddr(raw.Range[0])
		if err != nil {
			return nil, pool.Spec{}, err
		}
		sub.End, err = netip.ParseAddr(raw.Range[1])
		if err != nil {
			return nil, pool.Spec{}, err
		}
	}
	if raw.NextServer != "" {
		sub.NextServer, err = netip.ParseAddr(raw.NextServer)
		if err != nil {
			return nil, pool.Spec{}, err
		}
	}
	for code, value := range cfg.Options {
		sub.Options[code] = value
	}
	for code, value := range raw.Options {
		sub.Options[code] = value
	}
	if raw.VLAN != nil {
		if v, ok := vlans[*raw.VLAN]; ok {
			sub.PCP = v.Priority
			for code, value := range v.Options {
				sub.Options[code] = value
			}
			if v.Match != nil && v.Match.LinkSelection != "" {
				sub.LinkSelection, _ = netip.ParseAddr(v.Match.LinkSelection)
			}
		}
	}
	for _, v := range vlans {
		if v.SubnetRef == raw.ID {
			if v.Priority > 0 {
				sub.PCP = v.Priority
			}
			for code, value := range v.Options {
				sub.Options[code] = value
			}
			if v.Match != nil && v.Match.LinkSelection != "" {
				if ip, err := netip.ParseAddr(v.Match.LinkSelection); err == nil {
					sub.LinkSelection = ip
				}
			}
			if sub.VLAN == nil {
				id := v.ID
				sub.VLAN = &id
			}
		}
	}
	var reservations []config.Reservation
	for _, r := range raw.Reservations {
		if r.SubnetID == "" {
			r.SubnetID = raw.ID
		}
		r.MAC = model.NormalizeMAC(r.MAC)
		reservations = append(reservations, r)
	}
	for _, r := range cfg.Reservations {
		if r.SubnetID == raw.ID {
			r.MAC = model.NormalizeMAC(r.MAC)
			reservations = append(reservations, r)
		}
	}
	sub.Reservations = reservations

	spec := pool.Spec{
		ID:      sub.ID,
		Prefix:  sub.Prefix,
		Start:   sub.Start,
		End:     sub.End,
		Gateway: sub.Gateway,
	}
	if sub.VLAN != nil {
		spec.VLAN = *sub.VLAN
	}
	for _, r := range reservations {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			return nil, pool.Spec{}, err
		}
		spec.Reservations = append(spec.Reservations, pool.Reservation{
			IP:       ip,
			MAC:      r.MAC,
			ClientID: r.ClientID,
			Hostname: r.Hostname,
		})
	}
	return sub, spec, nil
}

func catalogParts(snap *Snapshot) (vlans []model.VLAN, subnets []model.Subnet, relays []model.Relay, reservations []model.Reservation) {
	for _, v := range snap.Cfg.VLANs {
		vlans = append(vlans, model.VLAN{
			ID: v.ID, Name: v.Name, Interface: v.Interface, Priority: v.Priority, Source: v.Source, SubnetID: v.SubnetRef,
		})
	}
	for _, sub := range snap.Subnets {
		opts := map[string]string{}
		for code, value := range sub.Options {
			opts[strconv.Itoa(code)] = value
		}
		dns := make([]string, len(sub.DNS))
		for i, ip := range sub.DNS {
			dns[i] = ip.String()
		}
		row := model.Subnet{
			ID:         sub.ID,
			Network:    sub.Prefix.String(),
			RangeStart: addrString(sub.Start),
			RangeEnd:   addrString(sub.End),
			Gateway:    addrString(sub.Gateway),
			VLANID:     sub.VLAN,
			Domain:     sub.Domain,
			DNS:        dns,
			Options:    opts,
			LeaseSec:   int(sub.Lease / time.Second),
		}
		subnets = append(subnets, row)
		for _, r := range sub.Reservations {
			reservations = append(reservations, model.Reservation{
				MAC: r.MAC, ClientID: r.ClientID, IP: r.IP, Hostname: r.Hostname, SubnetID: sub.ID,
			})
		}
	}
	for _, t := range snap.Cfg.Relay.TrustedRelays {
		if t.GIAddr == "" {
			continue
		}
		relays = append(relays, model.Relay{
			GIAddr: t.GIAddr, RemoteID: t.RemoteID, Vendor: t.Vendor, Trusted: true, ParserName: t.Parser, VLANID: t.VLAN, SubnetID: t.SubnetID,
		})
	}
	return vlans, subnets, relays, reservations
}

func bindingsOf(leases []model.Lease) []pool.Binding {
	out := make([]pool.Binding, 0, len(leases))
	for _, l := range leases {
		mac := l.MAC
		if l.State == model.StateDeclined {
			mac = "*held*"
		}
		out = append(out, pool.Binding{IP: l.IP, MAC: mac, ClientID: l.ClientID})
	}
	return out
}

func addrString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func prefixMask(p netip.Prefix) netip.Addr {
	m := net.CIDRMask(p.Bits(), 32)
	return netip.AddrFrom4([4]byte{m[0], m[1], m[2], m[3]})
}
