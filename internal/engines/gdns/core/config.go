// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"github.com/miekg/dns"
	validation "github.com/rkislov/gfw/internal/engines/gdns/dnssec"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type Config struct {
	UDPWorkers       int               `json:"udp_workers"`
	DNSSEC           validation.Config `json:"dnssec"`
	DoHListen        string            `json:"doh_listen"`
	DoTListen        string            `json:"dot_listen"`
	TLSCertFile      string            `json:"tls_cert_file"`
	TLSKeyFile       string            `json:"tls_key_file"`
	DNSListen        string            `json:"dns_listen"`
	HTTPListen       string            `json:"http_listen"`
	Mode             string            `json:"mode"`
	Upstreams        []string          `json:"upstreams"`
	AllowedClients   []string          `json:"allowed_clients"`
	QueryLogLimit    int               `json:"query_log_limit"`
	QueryLog         bool              `json:"query_log"`
	CacheSize        int               `json:"cache_size"`
	DNSSECValidation bool              `json:"dnssec_validation"`
	Zones            []Zone            `json:"zones"`
	Blocked          []string          `json:"blocked"`
	FeedExceptions   []string          `json:"feed_exceptions,omitempty"`
	Feeds            []Feed            `json:"feeds"`
}
type Zone struct {
	Transfer    ZoneTransfer   `json:"transfer,omitempty"`
	Secondary   SecondaryState `json:"secondary,omitempty"`
	RecordViews []RecordView   `json:"record_views,omitempty"`
	Name        string         `json:"name"`
	Kind        string         `json:"kind"`
	Clients     []string       `json:"clients"`
	Records     []string       `json:"records"`
	Servers     []string       `json:"servers"`
}
type Feed struct {
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Authorization string   `json:"authorization,omitempty"`
	Enabled       bool     `json:"enabled"`
	Domains       []string `json:"domains,omitempty"`
	Updated       string   `json:"updated,omitempty"`
}

func DefaultConfig() Config {
	return Config{DNSSEC: validation.DefaultConfig(),
		DNSListen: "127.0.0.1:1053", HTTPListen: "127.0.0.1:8080", Mode: "recursive", Upstreams: []string{"1.1.1.1:53", "9.9.9.9:53"},
		AllowedClients: []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}, CacheSize: 10000, QueryLog: true, QueryLogLimit: 10000,
		Zones: []Zone{{Name: "home.arpa.", Kind: "primary", Clients: []string{}, Records: []string{"home.arpa. 300 IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 600 86400 300", "home.arpa. 300 IN NS ns.home.arpa.", "ns.home.arpa. 300 IN A 192.168.1.1", "router.home.arpa. 300 IN A 192.168.1.1"}, Servers: []string{}}}, Blocked: []string{}, Feeds: []Feed{},
	}
}

type compiledZone struct {
	recordViews       map[netip.Prefix]*recordLayer
	recordViewLengths []int
	Zone
	clients []netip.Prefix
	records map[string]map[uint16][]dns.RR
	viewKey string
	soa     []dns.RR
	nodes   map[string]struct{}
}
type zoneViews struct {
	fallback *compiledZone
	prefixes map[netip.Prefix]*compiledZone
	lengths  []int
}
type snapshot struct {
	validator   *validation.Validator
	config      Config
	zones       map[string]*zoneViews
	blocked     map[string]struct{}
	feedBlocked map[string]struct{}
	feedExcept  map[string]struct{}
	allowed     []netip.Prefix
}

func canonical(s string) string { return dns.CanonicalName(dns.Fqdn(strings.TrimSpace(s))) }
func prefixes(values []string) (out []netip.Prefix, err error) {
	for _, s := range values {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return nil, fmt.Errorf("invalid CIDR %q", s)
		}
		out = append(out, p.Masked())
	}
	return
}
func validName(s string) bool {
	_, ok := dns.IsDomainName(s)
	return ok && !strings.ContainsAny(s, " /:@\t\n")
}
func validateServers(ss []string) error {
	for _, s := range ss {
		host, port, err := net.SplitHostPort(s)
		p, e := strconv.Atoi(port)
		if err != nil || e != nil || p < 1 || p > 65535 {
			return fmt.Errorf("DNS server must be an IP address with a valid port: %q", s)
		}
		if _, err = netip.ParseAddr(host); err != nil {
			return fmt.Errorf("DNS server must be an IP: %q", s)
		}
	}
	return nil
}
func cloneConfig(c Config) Config {
	c.DNSSEC.TrustAnchors = slices.Clone(c.DNSSEC.TrustAnchors)
	c.DNSSEC.ExemptZones = slices.Clone(c.DNSSEC.ExemptZones)
	if c.DNSSEC.MaxNSEC3Iterations != nil {
		v := *c.DNSSEC.MaxNSEC3Iterations
		c.DNSSEC.MaxNSEC3Iterations = &v
	}
	c.Upstreams = slices.Clone(c.Upstreams)
	c.AllowedClients = slices.Clone(c.AllowedClients)
	c.Blocked = slices.Clone(c.Blocked)
	c.FeedExceptions = slices.Clone(c.FeedExceptions)
	c.Zones = slices.Clone(c.Zones)
	c.Feeds = slices.Clone(c.Feeds)
	for i := range c.Zones {
		z := &c.Zones[i]
		z.Transfer.Allow = slices.Clone(z.Transfer.Allow)
		z.Clients = slices.Clone(z.Clients)
		z.Records = slices.Clone(z.Records)
		z.Servers = slices.Clone(z.Servers)
		z.RecordViews = slices.Clone(z.RecordViews)
		for j := range z.RecordViews {
			z.RecordViews[j].Clients = slices.Clone(z.RecordViews[j].Clients)
			z.RecordViews[j].Records = slices.Clone(z.RecordViews[j].Records)
		}
	}
	for i := range c.Feeds {
		c.Feeds[i].Domains = slices.Clone(c.Feeds[i].Domains)
	}
	return c
}
func compile(c Config) (*snapshot, error) {
	c = cloneConfig(c)
	if c.UDPWorkers < 0 || c.UDPWorkers > 64 {
		return nil, fmt.Errorf("udp_workers must be 0..64")
	}
	if c.QueryLogLimit == 0 {
		c.QueryLogLimit = 10000
	}
	if c.QueryLogLimit < 100 || c.QueryLogLimit > 100000 {
		return nil, fmt.Errorf("query_log_limit must be 100..100000")
	}
	if c.Mode != "recursive" && c.Mode != "forward" {
		return nil, fmt.Errorf("mode must be recursive or forward")
	}
	if c.CacheSize < 0 || c.CacheSize > 1000000 {
		return nil, fmt.Errorf("cache_size must be 0..1000000")
	}
	var err error
	c.DNSSEC, err = validation.Normalize(c.DNSSEC)
	if err != nil {
		return nil, err
	}

	if (c.DoHListen != "" || c.DoTListen != "") && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return nil, fmt.Errorf("DoH/DoT require tls_cert_file and tls_key_file")
	}
	if c.DNSListen == "" || c.HTTPListen == "" {
		return nil, fmt.Errorf("DNS and HTTP listen addresses are required")
	}
	seenListeners := map[string]bool{}
	for _, a := range []string{c.DNSListen, c.HTTPListen, c.DoHListen, c.DoTListen} {
		if a == "" {
			continue
		}
		if seenListeners[a] {
			return nil, fmt.Errorf("duplicate TCP listen address: %s", a)
		}
		seenListeners[a] = true
		host, port, e := net.SplitHostPort(a)
		if e != nil {
			return nil, e
		}
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid listen port: %s", a)
		}
		if _, e = netip.ParseAddr(host); e != nil {
			return nil, fmt.Errorf("listen address must be a literal IP: %s", a)
		}
	}
	if e := validateServers(c.Upstreams); e != nil {
		return nil, e
	}
	if c.Mode == "forward" && len(c.Upstreams) == 0 {
		return nil, fmt.Errorf("forward mode requires upstreams")
	}
	s := &snapshot{config: c, zones: map[string]*zoneViews{}, blocked: map[string]struct{}{}, feedBlocked: map[string]struct{}{}, feedExcept: map[string]struct{}{}}
	if c.DNSSECValidation {
		s.validator, err = validation.New(c.DNSSEC)
		if err != nil {
			return nil, err
		}
	}
	s.allowed, err = prefixes(c.AllowedClients)
	if err != nil {
		return nil, err
	}
	for i, z := range c.Zones {
		z.Name = canonical(z.Name)
		if !validName(z.Name) {
			return nil, fmt.Errorf("invalid zone name")
		}
		c.Zones[i].Name = z.Name
		cz := &compiledZone{Zone: z, records: map[string]map[uint16][]dns.RR{}, nodes: map[string]struct{}{}, viewKey: strconv.Itoa(i)}
		cz.clients, err = prefixes(z.Clients)
		if err != nil {
			return nil, err
		}
		if err := validateTransfer(z, c.Zones); err != nil {
			return nil, err
		}
		switch z.Kind {
		case "primary", "secondary":
			if z.Kind == "secondary" {
				if len(z.Servers) == 0 {
					return nil, fmt.Errorf("secondary requires primary servers")
				}
				if err := validateServers(z.Servers); err != nil {
					return nil, err
				}
				if len(z.RecordViews) > 0 {
					return nil, fmt.Errorf("secondary cannot override transferred records")
				}
				if len(z.Records) == 0 {
					break
				}
			}
			for _, line := range z.Records {
				rr, e := dns.NewRR(line)
				if e != nil {
					return nil, e
				}
				h := rr.Header()
				h.Name = canonical(h.Name)
				for n := h.Name; dns.IsSubDomain(z.Name, n); {
					cz.nodes[n] = struct{}{}
					if n == z.Name {
						break
					}
					idx := strings.IndexByte(n, '.')
					if idx < 0 {
						break
					}
					n = n[idx+1:]
				}
				if h.Class != dns.ClassINET || !dns.IsSubDomain(z.Name, h.Name) {
					return nil, fmt.Errorf("record outside zone or non-IN: %s", line)
				}
				if cz.records[h.Name] == nil {
					cz.records[h.Name] = map[uint16][]dns.RR{}
				}
				cz.records[h.Name][h.Rrtype] = append(cz.records[h.Name][h.Rrtype], rr)
				if h.Rrtype == dns.TypeSOA && h.Name == z.Name {
					cz.soa = append(cz.soa, rr)
				}
			}
			if len(cz.soa) != 1 {
				return nil, fmt.Errorf("zone %s requires exactly one apex SOA", z.Name)
			}
			for name, types := range cz.records {
				if len(types[dns.TypeCNAME]) > 0 && (len(types) > 1 || len(types[dns.TypeCNAME]) > 1) {
					return nil, fmt.Errorf("CNAME must be exclusive: %s", name)
				}
			}
			if err := cz.compileRecordViews(); err != nil {
				return nil, err
			}
		case "forward", "stub":
			if len(z.RecordViews) > 0 {
				return nil, fmt.Errorf("record views require a primary zone")
			}
			if len(z.Servers) == 0 {
				return nil, fmt.Errorf("zone %s requires servers", z.Name)
			}
			if e := validateServers(z.Servers); e != nil {
				return nil, e
			}
		default:
			return nil, fmt.Errorf("unknown zone kind %q", z.Kind)
		}
		views := s.zones[z.Name]
		if views == nil {
			views = &zoneViews{prefixes: map[netip.Prefix]*compiledZone{}}
			s.zones[z.Name] = views
		}
		if len(cz.clients) == 0 {
			if views.fallback != nil {
				return nil, fmt.Errorf("duplicate default view: %s", z.Name)
			}
			views.fallback = cz
		}
		for _, p := range cz.clients {
			if views.prefixes[p] != nil {
				return nil, fmt.Errorf("duplicate view CIDR %s for %s", p, z.Name)
			}
			views.prefixes[p] = cz
			if !slices.Contains(views.lengths, p.Bits()) {
				views.lengths = append(views.lengths, p.Bits())
			}
		}
		slices.Sort(views.lengths)
		slices.Reverse(views.lengths)
	}
	for _, d := range c.Blocked {
		if !validName(d) {
			return nil, fmt.Errorf("invalid blocked domain %q", d)
		}
		s.blocked[canonical(d)] = struct{}{}
	}
	for _, d := range c.FeedExceptions {
		if !validName(d) {
			return nil, fmt.Errorf("invalid feed exception %q", d)
		}
		s.feedExcept[canonical(d)] = struct{}{}
	}
	for _, f := range c.Feeds {
		if f.Enabled {
			for _, d := range f.Domains {
				if !validName(d) {
					return nil, fmt.Errorf("invalid feed domain %q", d)
				}
				s.feedBlocked[canonical(d)] = struct{}{}
			}
		}
	}
	s.config = c
	return s, nil
}
func (s *snapshot) zone(name string, ip netip.Addr) *compiledZone {
	for n := name; ; {
		if views := s.zones[n]; views != nil {
			for _, bits := range views.lengths {
				if bits > ip.BitLen() {
					continue
				}
				p := netip.PrefixFrom(ip, bits).Masked()
				if z := views.prefixes[p]; z != nil {
					return z
				}
			}
			if views.fallback != nil {
				return views.fallback
			}
		}

		if n == "." {
			break
		}
		idx := strings.IndexByte(n, '.')
		if idx < 0 || idx == len(n)-1 {
			n = "."
		} else {
			n = n[idx+1:]
		}
	}
	return nil
}
func (s *snapshot) isBlocked(name string) bool {
	feedMatch, feedExcept := false, false
	for n := name; n != "."; {
		if _, ok := s.blocked[n]; ok {
			return true
		}
		if _, ok := s.feedBlocked[n]; ok {
			feedMatch = true
		}
		if _, ok := s.feedExcept[n]; ok {
			feedExcept = true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i == len(n)-1 {
			break
		}
		n = n[i+1:]
	}
	return feedMatch && !feedExcept
}
