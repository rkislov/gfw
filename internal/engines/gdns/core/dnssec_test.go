// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"crypto"
	"github.com/miekg/dns"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSSECFlagsCacheAndCD(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(rr dns.RR) []dns.RR {
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: rr.Header().Rrtype, Algorithm: key.Algorithm, OrigTtl: 300, Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: "."}
		if err := sig.Sign(private.(crypto.Signer), []dns.RR{rr}); err != nil {
			t.Fatal(err)
		}
		return []dns.RR{rr, sig}
	}
	txt, _ := dns.NewRR(`. 300 IN TXT "authentic"`)
	good := sign(txt)
	keys := sign(key)
	var tamper atomic.Bool
	var calls atomic.Int64
	server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		calls.Add(1)
		m := new(dns.Msg)
		m.SetReply(q)
		m.AuthenticatedData = true
		if q.Question[0].Qtype == dns.TypeDNSKEY {
			m.Answer = copyRRs(keys, "")
		} else {
			m.Answer = copyRRs(good, "")
			if tamper.Load() {
				m.Answer[0].(*dns.TXT).Txt = []string{"tampered"}
			}
		}
		_ = w.WriteMsg(m)
	})
	c := DefaultConfig()
	c.Mode = "forward"
	c.Upstreams = []string{server}
	c.DNSSECValidation = true
	c.DNSSEC.TrustAnchors = []string{key.ToDS(dns.SHA256).String()}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(do, ad, cd bool) *dns.Msg {
		q := query(".", dns.TypeTXT)
		q.AuthenticatedData = ad
		q.CheckingDisabled = cd
		if do {
			q.SetEdns0(1232, true)
		}
		m, _ := e.Resolve(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
		return m
	}
	for _, flags := range []struct{ do, ad, wantAD bool }{{true, false, true}, {false, false, false}, {false, true, true}} {
		for n := 0; n < 2; n++ {
			m := resolve(flags.do, flags.ad, false)
			if m.Rcode != 0 || m.AuthenticatedData != flags.wantAD {
				t.Fatalf("flags/cache: %v", m)
			}
			if !flags.do && len(m.Answer) != 1 {
				t.Fatal("RRSIG leaked to non-DO client")
			}
		}
	}
	before := calls.Load()
	resolve(true, false, false)
	if calls.Load() != before {
		t.Fatal("validated cache missed")
	}
	tamper.Store(true)
	m := resolve(true, false, true)
	if m.Rcode != 0 || m.AuthenticatedData || !m.CheckingDisabled {
		t.Fatalf("CD bypass: %v", m)
	}
	m = resolve(true, false, false)
	if !m.AuthenticatedData || m.Answer[0].(*dns.TXT).Txt[0] != "authentic" {
		t.Fatal("CD poisoned validated cache")
	}
	if err := e.Update(c, func(Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m = resolve(true, false, false)
	if m.Rcode != dns.RcodeServerFailure || m.AuthenticatedData {
		t.Fatalf("bogus accepted: %v", m)
	}
	if m.IsEdns0() == nil || len(m.IsEdns0().Option) == 0 {
		t.Fatal("missing DNSSEC EDE")
	}
	c.DNSSEC.IgnoreCD = true
	if err := e.Update(c, func(Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if m = resolve(true, false, true); m.Rcode != dns.RcodeServerFailure {
		t.Fatal("ignore-CD did not enforce validation")
	}
}

func TestSecureCacheRechecksSignaturePeriod(t *testing.T) {
	c := newCache(64)
	m := new(dns.Msg)
	m.Rcode = 0
	m.AuthenticatedData = true
	a, _ := dns.NewRR("example. 300 IN A 192.0.2.1")
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 300}, Expiration: uint32(time.Now().Add(-time.Minute).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix())}
	m.Answer = []dns.RR{a, sig}
	c.put("secure", m)
	if c.get("secure") != nil {
		t.Fatal("expired signature served from secure cache")
	}
}
