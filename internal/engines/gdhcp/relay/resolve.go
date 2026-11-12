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

package relay

import "net/netip"

const (
	SourceLinkSelection = "option82_sub5_link_selection"
	SourceCircuitID     = "option82_sub1_circuit_id"
	SourceGIAddr        = "giaddr"
	SourceDefaultVLAN   = "default_vlan"
)

// Network is a subnet the resolver can select.
type Network struct {
	ID            string
	VLAN          *int
	Prefix        netip.Prefix
	LinkSelection netip.Addr
	CircuitParser string
}

// Route maps a relay giaddr to a VLAN or subnet.
type Route struct {
	GIAddr   string
	VLAN     *int
	SubnetID string
}

// Request carries the signals available on one DHCP message.
type Request struct {
	LinkSelection netip.Addr
	CircuitID     string
	GIAddr        netip.Addr
	DefaultVLAN   *int
	DefaultPool   string
}

// Decision is the result of walking vlan_source_priority.
type Decision struct {
	SubnetID    string
	VLAN        *int
	Source      string
	Parser      string
	UnknownVLAN bool
	UnknownID   int
	CircuitID   string
}

// Resolve walks priority and returns the first source that identifies a subnet.
// A circuit id that names a VLAN which is not configured stops the walk: that
// is an unknown VLAN, not an unrecognized circuit id.
func Resolve(priority []string, parsers []Parser, nets []Network, routes []Route, req Request) (Decision, bool) {
	if len(priority) == 0 {
		priority = []string{SourceLinkSelection, SourceCircuitID, SourceGIAddr, SourceDefaultVLAN}
	}
	for _, src := range priority {
		switch src {
		case SourceLinkSelection:
			if !req.LinkSelection.IsValid() || req.LinkSelection.IsUnspecified() {
				continue
			}
			if n, ok := matchLink(nets, req.LinkSelection); ok {
				return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
			}
		case SourceCircuitID:
			if req.CircuitID == "" {
				continue
			}
			vlan, parser, _, ok := MatchVLAN(parsers, req.CircuitID, "")
			if !ok {
				if v, okBin := BinaryVLAN([]byte(req.CircuitID)); okBin {
					vlan, parser, ok = v, "binary", true
				}
			}
			if !ok {
				continue
			}
			if n, found := networkByVLAN(nets, vlan); found {
				return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, Parser: parser, CircuitID: req.CircuitID}, true
			}
			return Decision{Source: src, Parser: parser, UnknownVLAN: true, UnknownID: vlan, CircuitID: req.CircuitID}, false
		case SourceGIAddr:
			if !req.GIAddr.IsValid() || req.GIAddr.IsUnspecified() {
				continue
			}
			gi := req.GIAddr.String()
			for _, r := range routes {
				if r.GIAddr != gi {
					continue
				}
				if r.SubnetID != "" {
					if n, ok := networkByID(nets, r.SubnetID); ok {
						return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
					}
				}
				if r.VLAN != nil {
					if n, ok := networkByVLAN(nets, *r.VLAN); ok {
						return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
					}
				}
			}
			if n, ok := longestPrefix(nets, req.GIAddr); ok {
				return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
			}
		case SourceDefaultVLAN:
			if req.DefaultPool != "" {
				if n, ok := networkByID(nets, req.DefaultPool); ok {
					return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
				}
			}
			if req.DefaultVLAN != nil {
				if n, ok := networkByVLAN(nets, *req.DefaultVLAN); ok {
					return Decision{SubnetID: n.ID, VLAN: n.VLAN, Source: src, CircuitID: req.CircuitID}, true
				}
			}
		}
	}
	return Decision{}, false
}

func matchLink(nets []Network, ip netip.Addr) (Network, bool) {
	var exact *Network
	for i := range nets {
		if nets[i].LinkSelection.IsValid() && nets[i].LinkSelection == ip {
			exact = &nets[i]
			break
		}
	}
	if exact != nil {
		return *exact, true
	}
	return longestPrefix(nets, ip)
}

func longestPrefix(nets []Network, ip netip.Addr) (Network, bool) {
	bestBits := -1
	var best Network
	found := false
	for _, n := range nets {
		if !n.Prefix.IsValid() || !n.Prefix.Contains(ip) {
			continue
		}
		if n.Prefix.Bits() > bestBits {
			bestBits = n.Prefix.Bits()
			best = n
			found = true
		}
	}
	return best, found
}

func networkByVLAN(nets []Network, vlan int) (Network, bool) {
	for _, n := range nets {
		if n.VLAN != nil && *n.VLAN == vlan {
			return n, true
		}
	}
	return Network{}, false
}

func networkByID(nets []Network, id string) (Network, bool) {
	for _, n := range nets {
		if n.ID == id {
			return n, true
		}
	}
	return Network{}, false
}
