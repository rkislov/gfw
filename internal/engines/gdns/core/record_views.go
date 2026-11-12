// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"github.com/miekg/dns"
	"net/netip"
	"slices"
	"strings"
)

// RecordView overlays individual RRsets in one primary zone for matching sources.
type RecordView struct {
	Clients []string `json:"clients"`
	Records []string `json:"records"`
}
type rrsets map[uint16][]dns.RR
type ownerRecords map[string]rrsets
type recordLayer struct {
	records ownerRecords
	nodes   map[string]struct{}
}

func mergeRRsets(base, overlay rrsets) rrsets {
	out := rrsets{}
	if len(overlay[dns.TypeCNAME]) == 0 && len(base[dns.TypeCNAME]) == 0 {
		for typ, set := range base {
			out[typ] = set
		}
	}
	for typ, set := range overlay {
		out[typ] = set
	}
	return out
}
func (cz *compiledZone) compileRecordViews() error {
	raw := map[netip.Prefix]ownerRecords{}
	cz.recordViews = map[netip.Prefix]*recordLayer{}
	for _, view := range cz.RecordViews {
		ps, err := prefixes(view.Clients)
		if err != nil {
			return err
		}
		if len(ps) == 0 || len(view.Records) == 0 {
			return fmt.Errorf("record view requires CIDRs and records")
		}
		records := ownerRecords{}
		for _, line := range view.Records {
			rr, e := dns.NewRR(line)
			if e != nil {
				return e
			}
			h := rr.Header()
			h.Name = canonical(h.Name)
			if h.Class != dns.ClassINET || !dns.IsSubDomain(cz.Name, h.Name) || h.Rrtype == dns.TypeSOA {
				return fmt.Errorf("split record must be IN, inside %s and not SOA", cz.Name)
			}
			if records[h.Name] == nil {
				records[h.Name] = rrsets{}
			}
			records[h.Name][h.Rrtype] = append(records[h.Name][h.Rrtype], rr)
		}
		for name, types := range records {
			if len(types[dns.TypeCNAME]) > 0 && (len(types) > 1 || len(types[dns.TypeCNAME]) > 1) {
				return fmt.Errorf("split CNAME must be exclusive: %s", name)
			}
		}
		for _, p := range ps {
			if raw[p] == nil {
				raw[p] = ownerRecords{}
			}
			for name, types := range records {
				if raw[p][name] == nil {
					raw[p][name] = rrsets{}
				}
				for typ, set := range types {
					if raw[p][name][typ] != nil {
						return fmt.Errorf("duplicate split RRset for %s type %d CIDR %s", name, typ, p)
					}
					raw[p][name][typ] = set
				}
			}
		}
	}
	for _, records := range raw {
		for name, types := range records {
			if len(types[dns.TypeCNAME]) > 0 && (len(types) > 1 || len(types[dns.TypeCNAME]) > 1) {
				return fmt.Errorf("conflicting split CNAME: %s", name)
			}
		}
	}

	for p, records := range raw {
		layer := &recordLayer{records: ownerRecords{}, nodes: map[string]struct{}{}}
		for name := range records {
			effective := rrsets{}
			for typ, set := range cz.records[name] {
				effective[typ] = set
			}
			for bits := 0; bits <= p.Bits(); bits++ {
				parent := netip.PrefixFrom(p.Addr(), bits).Masked()
				if overrides := raw[parent][name]; len(overrides) > 0 {
					effective = mergeRRsets(effective, overrides)
				}
			}
			layer.records[name] = effective
			for n := name; dns.IsSubDomain(cz.Name, n); {
				layer.nodes[n] = struct{}{}
				if n == cz.Name {
					break
				}
				i := strings.IndexByte(n, '.')
				if i < 0 {
					break
				}
				n = n[i+1:]
			}
		}
		cz.recordViews[p] = layer
		if !slices.Contains(cz.recordViewLengths, p.Bits()) {
			cz.recordViewLengths = append(cz.recordViewLengths, p.Bits())
		}
	}
	slices.Sort(cz.recordViewLengths)
	slices.Reverse(cz.recordViewLengths)
	return nil
}
func (z *compiledZone) recordsFor(name string, ip netip.Addr) (rrsets, bool) {
	for _, bits := range z.recordViewLengths {
		if bits > ip.BitLen() {
			continue
		}
		if layer := z.recordViews[netip.PrefixFrom(ip, bits).Masked()]; layer != nil {
			if sets, ok := layer.records[name]; ok {
				return sets, true
			}
		}
	}
	sets, ok := z.records[name]
	return sets, ok
}
func (z *compiledZone) nodeExists(name string, ip netip.Addr) bool {
	if _, ok := z.nodes[name]; ok {
		return true
	}
	for _, bits := range z.recordViewLengths {
		if bits > ip.BitLen() {
			continue
		}
		if layer := z.recordViews[netip.PrefixFrom(ip, bits).Masked()]; layer != nil {
			if _, ok := layer.nodes[name]; ok {
				return true
			}
		}
	}
	return false
}
