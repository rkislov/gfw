// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dnssec

import (
	"context"
	"crypto"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

type signer struct {
	key     *dns.DNSKEY
	private crypto.Signer
}

func newSigner(t *testing.T, name string) signer {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	p, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key, p.(crypto.Signer)}
}
func (s signer) sign(t *testing.T, rrs []dns.RR) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: rrs[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: rrs[0].Header().Rrtype, Algorithm: s.key.Algorithm, Labels: uint8(dns.CountLabel(rrs[0].Header().Name)), OrigTtl: rrs[0].Header().Ttl, Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()), KeyTag: s.key.KeyTag(), SignerName: s.key.Hdr.Name}
	if strings.HasPrefix(sig.Hdr.Name, "*.") {
		sig.Labels--
	}
	if err := sig.Sign(s.private, rrs); err != nil {
		t.Fatal(err)
	}
	return sig
}
func rr(t *testing.T, line string) dns.RR {
	t.Helper()
	r, e := dns.NewRR(line)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func reply(name string, typ uint16, answer, ns []dns.RR, rcode int) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	m := new(dns.Msg)
	m.SetReply(q)
	m.Authoritative = true
	m.Rcode = rcode
	m.Answer = answer
	m.Ns = ns
	return m
}
func signed(t *testing.T, s signer, records ...dns.RR) []dns.RR {
	return append(append([]dns.RR{}, records...), s.sign(t, records))
}

type hierarchy struct {
	root, parent, child signer
	messages            map[string]*dns.Msg
	config              Config
	t                   *testing.T
}

func messageKey(n string, typ uint16) string { return canonical(n) + fmt.Sprint(typ) }
func fixture(t *testing.T) *hierarchy {
	h := &hierarchy{root: newSigner(t, "."), parent: newSigner(t, "test."), child: newSigner(t, "secure.test."), messages: map[string]*dns.Msg{}, t: t}
	h.config = DefaultConfig()
	h.config.TrustAnchors = []string{h.root.key.ToDS(dns.SHA256).String()}
	for _, s := range []signer{h.root, h.parent, h.child} {
		h.put(reply(s.key.Hdr.Name, dns.TypeDNSKEY, signed(t, s, s.key), nil, 0))
	}
	h.put(reply("test.", dns.TypeDS, signed(t, h.root, h.parent.key.ToDS(dns.SHA256)), nil, 0))
	h.put(reply("secure.test.", dns.TypeDS, signed(t, h.parent, h.child.key.ToDS(dns.SHA256)), nil, 0))
	h.put(h.nodata("www.secure.test.", dns.TypeDS, []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}))
	return h
}
func (h *hierarchy) put(m *dns.Msg) {
	h.messages[messageKey(m.Question[0].Name, m.Question[0].Qtype)] = m
}
func (h *hierarchy) fetch(_ context.Context, n string, typ uint16) (*dns.Msg, error) {
	m := h.messages[messageKey(n, typ)]
	if m == nil {
		return nil, fmt.Errorf("fixture missing %s %s", n, dns.TypeToString[typ])
	}
	return m.Copy(), nil
}
func (h *hierarchy) soa(s signer) dns.RR {
	return rr(h.t, fmt.Sprintf("%s 300 IN SOA ns.%s hostmaster.%s 1 3600 600 86400 60", s.key.Hdr.Name, s.key.Hdr.Name, s.key.Hdr.Name))
}
func (h *hierarchy) nodata(name string, typ uint16, bitmap []uint16) *dns.Msg {
	n := &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "zz.secure.test.", TypeBitMap: bitmap}
	authority := append(signed(h.t, h.child, h.soa(h.child)), signed(h.t, h.child, n)...)
	return reply(name, typ, nil, authority, 0)
}
func (h *hierarchy) positive() *dns.Msg {
	return reply("www.secure.test.", dns.TypeA, signed(h.t, h.child, rr(h.t, "www.secure.test. 300 IN A 192.0.2.1")), nil, 0)
}
func (h *hierarchy) validate(m *dns.Msg) (Result, error) {
	v, e := New(h.config)
	if e != nil {
		h.t.Fatal(e)
	}
	q := new(dns.Msg)
	q.Question = m.Question
	return v.Validate(context.Background(), q, m, "fixture", h.fetch)
}
func TestSecureChainAndCache(t *testing.T) {
	h := fixture(t)
	v, e := New(h.config)
	if e != nil {
		t.Fatal(e)
	}
	m := h.positive()
	q := new(dns.Msg)
	q.Question = m.Question
	result, e := v.Validate(context.Background(), q, m, "fixture", h.fetch)
	if e != nil || !result.Message.AuthenticatedData || result.State != "secure" {
		t.Fatalf("%+v %v", result, e)
	}
	if result.Message.Answer[0].Header().Ttl > 60 {
		t.Fatal("chain denial TTL not bounded")
	}
	if m.Answer[0].Header().Ttl != 300 {
		t.Fatal("validator mutated source message")
	}
	h.messages = map[string]*dns.Msg{}
	result, e = v.Validate(context.Background(), q, m, "fixture", h.fetch)
	if e != nil || !result.Message.AuthenticatedData {
		t.Fatal("validated key cache failed", e)
	}
	if _, e = v.Validate(context.Background(), q, m, "other-view", h.fetch); e == nil {
		t.Fatal("DNSSEC key cache leaked between routes")
	}
}
func TestBogusSignaturesAndChain(t *testing.T) {
	for _, scenario := range []string{"tamper", "missing-signature", "wrong-ds", "expired", "future", "rogue-key", "missing-dnskey"} {
		t.Run(scenario, func(t *testing.T) {
			h := fixture(t)
			m := h.positive()
			switch scenario {
			case "tamper":
				m.Answer[0].(*dns.A).A = net.ParseIP("192.0.2.2")
			case "missing-signature":
				m.Answer = m.Answer[:1]
			case "wrong-ds":
				ds := h.child.key.ToDS(dns.SHA256)
				ds.Digest = strings.Repeat("00", 32)
				h.put(reply("secure.test.", dns.TypeDS, signed(t, h.parent, ds), nil, 0))
			case "expired":
				sig := m.Answer[1].(*dns.RRSIG)
				sig.Expiration = uint32(time.Now().Add(-time.Minute).Unix())
			case "future":
				sig := m.Answer[1].(*dns.RRSIG)
				sig.Inception = uint32(time.Now().Add(time.Hour).Unix())
			case "rogue-key":
				rogue := newSigner(t, "secure.test.")
				h.put(reply("secure.test.", dns.TypeDNSKEY, signed(t, rogue, h.child.key, rogue.key), nil, 0))
			case "missing-dnskey":
				h.put(reply("secure.test.", dns.TypeDNSKEY, nil, nil, 0))
			}
			if result, err := h.validate(m); err == nil {
				t.Fatalf("bogus data accepted: %+v", result)
			}
		})
	}
}
func TestUnsignedDelegationAndStrippedDS(t *testing.T) {
	for _, scenario := range []string{"unsigned", "stripped-ds", "unsupported-ds"} {
		t.Run(scenario, func(t *testing.T) {
			h := fixture(t)
			switch scenario {
			case "unsigned":
				n := rr(t, "secure.test. 300 IN NSEC z.test. NS RRSIG NSEC")
				h.put(reply("secure.test.", dns.TypeDS, nil, signed(t, h.parent, n), 0))
			case "stripped-ds":
				h.put(reply("secure.test.", dns.TypeDS, nil, signed(t, h.parent, h.soa(h.parent)), 0))
			case "unsupported-ds":
				ds := h.child.key.ToDS(dns.SHA256)
				ds.DigestType = 250
				h.put(reply("secure.test.", dns.TypeDS, signed(t, h.parent, ds), nil, 0))
			}
			m := h.positive()
			m.Answer = m.Answer[:1]
			m.AuthenticatedData = true
			result, err := h.validate(m)
			if scenario == "stripped-ds" {
				if err == nil {
					t.Fatal("stripped DS downgraded signed child")
				}
				return
			}
			if err != nil || result.Message.AuthenticatedData || result.State != "insecure" {
				t.Fatalf("insecure delegation: %+v %v", result, err)
			}
		})
	}
}
func (h *hierarchy) nxdomain(name string, typ uint16) *dns.Msg {
	a := rr(h.t, "secure.test. 300 IN NSEC a.secure.test. SOA NS RRSIG NSEC DNSKEY")
	b := rr(h.t, "a.secure.test. 300 IN NSEC z.secure.test. A RRSIG NSEC")
	ns := signed(h.t, h.child, h.soa(h.child))
	ns = append(ns, signed(h.t, h.child, a)...)
	ns = append(ns, signed(h.t, h.child, b)...)
	return reply(name, typ, nil, ns, dns.RcodeNameError)
}
func TestNSECNegativeAnswers(t *testing.T) {
	h := fixture(t)
	m := h.nxdomain("missing.secure.test.", dns.TypeA)
	h.put(h.nxdomain("missing.secure.test.", dns.TypeDS))
	result, e := h.validate(m)
	if e != nil || !result.Message.AuthenticatedData || result.Message.Rcode != dns.RcodeNameError || !hasSOAFor(result.Message.Ns, "secure.test.") {
		t.Fatalf("NXDOMAIN %+v %v", result, e)
	}
	m = h.nodata("www.secure.test.", dns.TypeAAAA, []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG})
	result, e = h.validate(m)
	if e != nil || !result.Message.AuthenticatedData || len(result.Message.Answer) != 0 {
		t.Fatalf("NODATA %+v %v", result, e)
	}
	m = h.nxdomain("missing.secure.test.", dns.TypeA)
	m.Ns = signed(t, h.child, h.soa(h.child))
	if _, e = h.validate(m); e == nil {
		t.Fatal("missing authenticated denial accepted")
	}
}
func (h *hierarchy) nsec3Set(s signer, names []string, flags uint8, iterations uint16) []dns.RR {
	hashes := map[string]string{}
	ordered := []string{}
	for _, name := range names {
		hash := dns.HashName(name, dns.SHA1, iterations, "")
		hashes[hash] = name
		ordered = append(ordered, hash)
	}
	sort.Strings(ordered)
	records := []dns.RR{}
	for i, hash := range ordered {
		types := []uint16{dns.TypeA, dns.TypeRRSIG}
		if hashes[hash] == s.key.Hdr.Name {
			types = []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeRRSIG}
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		n := &dns.NSEC3{Hdr: dns.RR_Header{Name: hash + "." + s.key.Hdr.Name, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300}, Hash: dns.SHA1, Flags: flags, Iterations: iterations, HashLength: 20, NextDomain: ordered[(i+1)%len(ordered)], TypeBitMap: types}
		records = append(records, signed(h.t, s, n)...)
	}
	return records
}
func TestNSEC3NegativeAndLimits(t *testing.T) {
	h := fixture(t)
	ns := signed(t, h.child, h.soa(h.child))
	ns = append(ns, h.nsec3Set(h.child, []string{"secure.test.", "a.secure.test.", "z.secure.test."}, 0, 0)...)
	name := "missing.secure.test."
	h.put(reply(name, dns.TypeDS, nil, ns, dns.RcodeNameError))
	m := reply(name, dns.TypeA, nil, ns, dns.RcodeNameError)
	result, e := h.validate(m)
	if e != nil || !result.Message.AuthenticatedData {
		t.Fatalf("NSEC3 NXDOMAIN %+v %v", result, e)
	}
	ns = signed(t, h.child, h.soa(h.child))
	ns = append(ns, h.nsec3Set(h.child, []string{"secure.test.", "www.secure.test."}, 0, 0)...)
	m = reply("www.secure.test.", dns.TypeAAAA, nil, ns, 0)
	result, e = h.validate(m)
	if e != nil || !result.Message.AuthenticatedData {
		t.Fatalf("NSEC3 NODATA %+v %v", result, e)
	}
	ns = h.nsec3Set(h.child, []string{"secure.test."}, 0, 151)
	m = reply(name, dns.TypeA, nil, ns, dns.RcodeNameError)
	if _, e = h.validate(m); e == nil {
		t.Fatal("excessive NSEC3 iterations accepted")
	}
}
func TestCustomExceptionIsExplicit(t *testing.T) {
	h := fixture(t)
	h.config.ExemptZones = []string{"secure.test."}
	m := h.positive()
	m.Answer = m.Answer[:1]
	result, e := h.validate(m)
	if e != nil || result.Message.AuthenticatedData {
		t.Fatal("explicit NTA failed", e)
	}
	h.config.ExemptZones = []string{"."}
	if _, e := New(h.config); e == nil {
		t.Fatal("root bypass accepted")
	}
}

func TestAliasesAndWildcard(t *testing.T) {
	for _, scenario := range []string{"cname", "cname-negative", "cname-unsigned-target", "dname", "bad-dname", "wildcard", "wildcard-missing-proof", "unrelated-answer"} {
		t.Run(scenario, func(t *testing.T) {
			h := fixture(t)
			m := h.positive()
			switch scenario {
			case "cname", "cname-negative", "cname-unsigned-target":
				alias := rr(t, "www.secure.test. 300 IN CNAME target.secure.test.")
				h.put(reply("www.secure.test.", dns.TypeDS, signed(t, h.child, alias), nil, 0))
				h.put(h.nodata("target.secure.test.", dns.TypeDS, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}))
				m.Answer = signed(t, h.child, alias)
				if scenario == "cname-negative" {
					negative := h.nxdomain("target.secure.test.", dns.TypeDS)
					h.put(negative)
					m.Ns = negative.Ns
					m.Rcode = dns.RcodeNameError
				} else {
					target := signed(t, h.child, rr(t, "target.secure.test. 300 IN A 192.0.2.9"))
					if scenario == "cname-unsigned-target" {
						target = target[:1]
					}
					m.Answer = append(m.Answer, target...)
				}
			case "dname", "bad-dname":
				d := rr(t, "alias.secure.test. 300 IN DNAME secure.test.")
				h.put(h.nodata("alias.secure.test.", dns.TypeDS, []uint16{dns.TypeDNAME, dns.TypeRRSIG, dns.TypeNSEC}))
				m.Question[0].Name = "www.alias.secure.test."
				synthesized := rr(t, "www.alias.secure.test. 300 IN CNAME www.secure.test.")
				if scenario == "bad-dname" {
					synthesized.(*dns.CNAME).Target = "attacker.test."
				}
				m.Answer = append(append(signed(t, h.child, d), synthesized), m.Answer...)
			case "wildcard", "wildcard-missing-proof":
				records := signed(t, h.child, rr(t, "*.secure.test. 300 IN A 192.0.2.1"))
				for _, record := range records {
					record.Header().Name = "www.secure.test."
				}
				m.Answer = records
				if scenario == "wildcard" {
					m.Ns = h.nxdomain("www.secure.test.", dns.TypeA).Ns
				}
			case "unrelated-answer":
				m.Answer = append(m.Answer, rr(t, "attacker.test. 300 IN A 192.0.2.66"))
				m.Extra = []dns.RR{rr(t, "ns.attacker.test. 300 IN A 192.0.2.66")}
			}
			result, err := h.validate(m)
			bad := scenario == "bad-dname" || scenario == "wildcard-missing-proof" || scenario == "cname-unsigned-target"
			if bad {
				if err == nil {
					t.Fatal("invalid alias/wildcard accepted")
				}
				return
			}
			if err != nil || !result.Message.AuthenticatedData {
				t.Fatalf("%+v %v", result, err)
			}
			for _, record := range result.Message.Answer {
				if record.Header().Name == "attacker.test." {
					t.Fatal("unrelated data retained under AD")
				}
			}
			if len(result.Message.Extra) != 0 {
				t.Fatal("untrusted additional retained")
			}
		})
	}
}

func TestNSEC3OptOutDoesNotSetAD(t *testing.T) {
	h := fixture(t)
	ns := signed(t, h.parent, h.soa(h.parent))
	ns = append(ns, h.nsec3Set(h.parent, []string{"test.", "a.test.", "z.test."}, 1, 0)...)
	h.put(reply("secure.test.", dns.TypeDS, nil, ns, 0))
	m := h.positive()
	m.Answer = m.Answer[:1]
	result, err := h.validate(m)
	if err != nil || result.Message.AuthenticatedData {
		t.Fatalf("opt-out %+v %v", result, err)
	}
}

func TestSignatureExpirationBoundsTTL(t *testing.T) {
	h := fixture(t)
	m := h.positive()
	sig := m.Answer[1].(*dns.RRSIG)
	sig.Expiration = uint32(time.Now().Add(5 * time.Second).Unix())
	if err := sig.Sign(h.child.private, m.Answer[:1]); err != nil {
		t.Fatal(err)
	}
	result, err := h.validate(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range result.Message.Answer {
		if record.Header().Ttl > 5 {
			t.Fatal("cached beyond signature expiry")
		}
	}
}

func TestCrossZoneAliasAndKeyRollover(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		t.Run(fmt.Sprint("unsigned-target=", unsigned), func(t *testing.T) {
			h := fixture(t)
			other := newSigner(t, "other.test.")
			alias := rr(t, "www.secure.test. 300 IN CNAME other.test.")
			h.put(reply("www.secure.test.", dns.TypeDS, signed(t, h.child, alias), nil, 0))
			if unsigned {
				h.put(reply("other.test.", dns.TypeDS, nil, signed(t, h.parent, rr(t, "other.test. 300 IN NSEC z.test. NS RRSIG NSEC")), 0))
			} else {
				h.put(reply("other.test.", dns.TypeDS, signed(t, h.parent, other.key.ToDS(dns.SHA256)), nil, 0))
				// The DS authenticates the KSK, and its signed DNSKEY RRset introduces a
				// second signing key. Answers signed by that key must work during rollover.
				zsk := newSigner(t, "other.test.")
				zsk.key.Flags = 256
				h.put(reply("other.test.", dns.TypeDNSKEY, signed(t, other, other.key, zsk.key), nil, 0))
				other = zsk
			}
			records := signed(t, other, rr(t, "other.test. 300 IN A 192.0.2.5"))
			if unsigned {
				records = records[:1]
			}
			m := reply("www.secure.test.", dns.TypeA, append(signed(t, h.child, alias), records...), nil, 0)
			result, err := h.validate(m)
			if err != nil || result.Message.AuthenticatedData == unsigned {
				t.Fatalf("cross-zone: %+v %v", result, err)
			}
		})
	}
}
