// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func query(name string, typ uint16) *dns.Msg { m := new(dns.Msg); m.SetQuestion(name, typ); return m }
func zone(name, ip string, clients ...string) Zone {
	return Zone{Name: name, Kind: "primary", Clients: clients, Records: []string{fmt.Sprintf("%s 300 IN SOA ns.%s hostmaster.%s 1 3600 600 86400 60", name, name, name), fmt.Sprintf("host.%s 60 IN A %s", name, ip)}}
}
func TestSplitZones(t *testing.T) {
	c := DefaultConfig()
	c.Zones = []Zone{zone("example.", "192.0.2.1"), zone("example.", "10.0.0.1", "10.0.0.0/8"), zone("example.", "10.1.0.1", "10.1.0.0/16")}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ client, want string }{{"127.0.0.1", "192.0.2.1"}, {"10.2.0.1", "10.0.0.1"}, {"10.1.3.5", "10.1.0.1"}} {
		r, _ := e.Resolve(context.Background(), query("HOST.example.", dns.TypeA), netip.MustParseAddr(tc.client))
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != tc.want {
			t.Fatalf("%s: %v", tc.client, r)
		}
	}
}
func TestPolicyAndAuthority(t *testing.T) {
	c := DefaultConfig()
	c.Blocked = []string{"bad.example"}
	z := zone("example.", "192.0.2.1")
	z.Records = append(z.Records, "*.example. 60 IN A 192.0.2.2", "leaf.branch.example. 60 IN A 192.0.2.3")
	c.Zones = []Zone{z}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	for _, tc := range []struct {
		name          string
		typ           uint16
		code, answers int
	}{{"host.example.", dns.TypeAAAA, 0, 0}, {"wild.example.", dns.TypeA, 0, 1}, {"branch.example.", dns.TypeA, 0, 0}, {"none.branch.example.", dns.TypeA, dns.RcodeNameError, 0}, {"child.bad.example.net.", dns.TypeA, -1, 0}} {
		if tc.code < 0 {
			continue
		}
		r, _ := e.Resolve(context.Background(), query(tc.name, tc.typ), ip)
		if r.Rcode != tc.code || len(r.Answer) != tc.answers || !r.Authoritative {
			t.Fatalf("%s: %v", tc.name, r)
		}
	}
	r, _ := e.Resolve(context.Background(), query("example.org.", dns.TypeA), netip.MustParseAddr("203.0.113.1"))
	if r.Rcode != dns.RcodeRefused {
		t.Fatal(r)
	}
	c.Zones = nil
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	r, result := e.Resolve(context.Background(), query("sub.bad.example.", dns.TypeA), ip)
	if result != "BLOCKED" || r.Rcode != dns.RcodeNameError {
		t.Fatal(r)
	}
}
func TestConfigIsolation(t *testing.T) {
	c := DefaultConfig()
	e, _ := New(c)
	c.Zones[0].Records[2] = "corrupted"
	copy := e.Config()
	copy.Zones[0].Records[0] = "broken"
	if e.Config().Zones[0].Records[0] == "broken" {
		t.Fatal("mutable snapshot")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				e.Resolve(context.Background(), query("router.home.arpa.", dns.TypeA), netip.MustParseAddr("127.0.0.1"))
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if err := e.Apply(e.Config()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func TestFeedAndBIND(t *testing.T) {
	text := "# feed\n0.0.0.0 ads.example tracker.example\n||malware.example^\nads.example\n"
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, _ = gz.Write([]byte(text))
	_ = gz.Close()
	domains, err := ParseFeed(&b)
	if err != nil || len(domains) != 3 {
		t.Fatalf("%v %v", domains, err)
	}
	if _, err = ParseFeed(strings.NewReader("https://not-a-domain/path")); err == nil {
		t.Fatal("invalid input accepted")
	}
	rrs, err := ParseZone(strings.NewReader("$ORIGIN example.\n$TTL 300\n@ IN SOA ns hostmaster (1 3600 600 86400 60)\n@ IN NS ns\nns IN A 192.0.2.1\n"), "example.")
	if err != nil || len(rrs) != 3 {
		t.Fatalf("%v %v", rrs, err)
	}
	_, err = ParseZone(strings.NewReader("$INCLUDE /etc/passwd"), "example.")
	if err == nil {
		t.Fatal("include permitted")
	}
}
func TestCache(t *testing.T) {
	c := newCache(64)
	q := query("example.", dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("example. 60 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	c.put("view-a", m)
	a := c.get("view-a")
	a.Answer[0].Header().Ttl = 0
	if c.get("view-a").Answer[0].Header().Ttl != 60 {
		t.Fatal("shared cache mutation")
	}
	if c.get("view-b") != nil {
		t.Fatal("view leakage")
	}
	s := c.shard("view-a")
	s.Lock()
	v := s.items["view-a"]
	v.at = time.Now().Add(-time.Minute)
	s.items["view-a"] = v
	s.Unlock()
	if c.get("view-a") != nil {
		t.Fatal("expired record")
	}
}
func TestDNSSECConfiguration(t *testing.T) {
	c := DefaultConfig()
	c.DNSSECValidation = true
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
	c.DNSSEC.TrustAnchors = []string{"invalid"}
	if _, err := New(c); err == nil {
		t.Fatal("invalid trust anchor accepted")
	}
}
func fakeDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = s.ActivateAndServe() }()
	t.Cleanup(func() { _ = s.Shutdown() })
	return pc.LocalAddr().String()
}
func TestForwardAndViewCache(t *testing.T) {
	var calls int
	var mu sync.Mutex
	server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		calls++
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(q)
		m.AuthenticatedData = true
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.5")
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})
	c := DefaultConfig()
	c.Mode = "forward"
	c.Upstreams = []string{server}
	c.Zones = append(c.Zones, Zone{Name: "example.", Kind: "forward", Clients: []string{"10.0.0.0/8"}, Servers: []string{server}})
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{"127.0.0.1", "127.0.0.1", "10.0.0.1", "10.0.0.1"} {
		r, _ := e.Resolve(context.Background(), query("example.", dns.TypeA), netip.MustParseAddr(client))
		if len(r.Answer) != 1 || r.AuthenticatedData {
			t.Fatal(r)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("want two independent view cache entries, calls=%d", calls)
	}
}
func TestStubAuthoritative(t *testing.T) {
	server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		if q.RecursionDesired {
			t.Error("stub sends RD")
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.8")
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})
	c := DefaultConfig()
	c.Zones = []Zone{{Name: "example.", Kind: "stub", Servers: []string{server}}}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := e.Resolve(context.Background(), query("example.", dns.TypeA), netip.MustParseAddr("127.0.0.1"))
	if len(r.Answer) != 1 {
		t.Fatal(r)
	}
}
func BenchmarkPrimary(b *testing.B) {
	c := DefaultConfig()
	e, _ := New(c)
	ip := netip.MustParseAddr("127.0.0.1")
	q := query("router.home.arpa.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Resolve(context.Background(), q, ip)
		}
	})
}
func BenchmarkBlocklistMillion(b *testing.B) {
	c := DefaultConfig()
	c.Blocked = make([]string, 1000000)
	for i := range c.Blocked {
		c.Blocked[i] = fmt.Sprintf("d%d.bad.example", i)
	}
	e, err := New(c)
	if err != nil {
		b.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	q := query("sub.d999999.bad.example.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Resolve(context.Background(), q, ip)
		}
	})
}
func BenchmarkCacheHit(b *testing.B) {
	c := DefaultConfig()
	e, _ := New(c)
	q := query("example.", dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR("example. 300 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	e.state.Load().cache.put("example./1/false/false", m)
	ip := netip.MustParseAddr("127.0.0.1")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Resolve(context.Background(), q, ip)
		}
	})
}

func TestConcurrentMisses(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.5")
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})
	c := DefaultConfig()
	c.Mode = "forward"
	c.Upstreams = []string{server}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, _ := e.Resolve(context.Background(), query("example.", dns.TypeA), netip.MustParseAddr("127.0.0.1"))
			if len(r.Answer) != 1 {
				t.Error("missing answer")
			}
		}()
	}
	close(start)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("duplicate upstream work: %d", calls)
	}
}

func TestReferralGlueBailiwick(t *testing.T) {
	a, _ := dns.NewRR("a.gtld-servers.net. 300 IN A 192.0.2.1")
	bad, _ := dns.NewRR("unrelated.example. 300 IN A 192.0.2.2")
	rrs := []dns.RR{a, bad}
	names := []string{"a.gtld-servers.net."}
	if got := glueServers(rrs, names, "."); len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Fatalf("root sibling glue rejected: %v", got)
	}
	if got := glueServers(rrs, names, "com."); len(got) != 0 {
		t.Fatalf("out-of-bailiwick glue accepted: %v", got)
	}
}
