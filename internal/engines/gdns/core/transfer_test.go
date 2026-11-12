// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func transferPrimary(t *testing.T, configure func(*Config)) (*Engine, string) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Zones[0].Transfer.Allow = []string{"127.0.0.0/8"}
	configure(&cfg)
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	s := &dns.Server{Listener: l, Handler: e, TsigProvider: e, NotifyStartedFunc: func() { close(ready) }}
	go s.ActivateAndServe()
	<-ready
	t.Cleanup(func() { s.Shutdown() })
	return e, l.Addr().String()
}
func TestSecondaryTransferTSIGAndExpiry(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	primary, addr := transferPrimary(t, func(c *Config) {
		c.Zones[0].Transfer.KeyName = "secondary-key."
		c.Zones[0].Transfer.Secret = secret
		c.Zones[0].RecordViews = []RecordView{{Clients: []string{"127.0.0.0/28"}, Records: []string{"router.home.arpa. 300 IN A 192.0.2.28", "only.home.arpa. 300 IN A 192.0.2.1"}}}
	})
	z := Zone{Name: "home.arpa.", Kind: "secondary", Servers: []string{addr}, Transfer: ZoneTransfer{KeyName: "secondary-key.", Secret: secret}}
	got, err := FetchSecondary(context.Background(), z)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secondary.Serial != 1 || got.Secondary.LastSuccess.IsZero() {
		t.Fatal(got.Secondary)
	}
	cfg := DefaultConfig()
	cfg.Zones = []Zone{got}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("router.home.arpa.", dns.TypeA)
	r := e.Answer(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
	if !r.Authoritative || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.28" {
		t.Fatal(r)
	}
	q.SetQuestion("only.home.arpa.", dns.TypeA)
	r = e.Answer(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
	if len(r.Answer) != 1 {
		t.Fatal(r)
	}
	again, err := FetchSecondary(context.Background(), got)
	if err != nil || !again.Secondary.LastSuccess.After(got.Secondary.LastSuccess) {
		t.Fatal(err)
	}
	cfg.Zones[0].Secondary.LastSuccess = time.Now().Add(-48 * time.Hour)
	if err := e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if r = e.Answer(context.Background(), q, netip.MustParseAddr("127.0.0.1")); r.Rcode != dns.RcodeServerFailure {
		t.Fatal(r)
	}
	bad := z
	bad.Transfer.Secret = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))
	if _, err := FetchSecondary(context.Background(), bad); err == nil {
		t.Fatal("wrong key accepted")
	}
	unsigned := z
	unsigned.Transfer = ZoneTransfer{}
	if _, err := FetchSecondary(context.Background(), unsigned); err == nil {
		t.Fatal("unsigned transfer accepted")
	}
	pc := primary.Config()
	pc.Zones[0].Transfer.Allow = nil
	if err := primary.Apply(pc); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchSecondary(context.Background(), z); err == nil {
		t.Fatal("default-deny ACL bypass")
	}
}
func TestSecondaryRejectsPartialAndOutOfZone(t *testing.T) {
	for _, bad := range []string{"partial", "outside", "boundary"} {
		t.Run(bad, func(t *testing.T) {
			soa, _ := dns.NewRR("home.arpa. 60 IN SOA ns.home.arpa. hostmaster.home.arpa. 9 60 10 120 60")
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ready := make(chan struct{})
			s := &dns.Server{Listener: l, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				m.Authoritative = true
				m.Answer = []dns.RR{dns.Copy(soa)}
				if q.Question[0].Qtype == dns.TypeAXFR {
					switch bad {
					case "outside":
						rr, _ := dns.NewRR("outside.example. 60 IN A 192.0.2.1")
						m.Answer = append(m.Answer, rr, dns.Copy(soa))
					case "boundary":
						end := dns.Copy(soa).(*dns.SOA)
						end.Serial++
						m.Answer = append(m.Answer, end)
					}
				}
				w.WriteMsg(m)
				if bad == "partial" && q.Question[0].Qtype == dns.TypeAXFR {
					w.Close()
				}
			})}
			go s.ActivateAndServe()
			<-ready
			defer s.Shutdown()
			if _, err := FetchSecondary(context.Background(), Zone{Name: "home.arpa.", Kind: "secondary", Servers: []string{l.Addr().String()}}); err == nil {
				t.Fatal("invalid transfer accepted")
			}
		})
	}
}
func TestSerialArithmetic(t *testing.T) {
	if !serialNewer(0, ^uint32(0)) || serialNewer(1, 1) || serialNewer(0, 1) || serialNewer(1<<31, 0) {
		t.Fatal("RFC 1982 arithmetic")
	}
}
func TestEmptySecondaryServfail(t *testing.T) {
	c := DefaultConfig()
	c.Zones = []Zone{{Name: "home.arpa.", Kind: "secondary", Servers: []string{"127.0.0.1:1"}}}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("home.arpa.", dns.TypeSOA)
	if r := e.Answer(context.Background(), q, netip.MustParseAddr("127.0.0.1")); r.Rcode != dns.RcodeServerFailure {
		t.Fatal(r)
	}
}

func TestPrimarySerialAdvancesOnEdits(t *testing.T) {
	c := DefaultConfig()
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Zones[0].Records = append(c.Zones[0].Records, "new.home.arpa. 60 IN A 192.0.2.2")
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	if zoneSOA(e.Config().Zones[0]).Serial != 2 {
		t.Fatal("record edit did not advance serial")
	}
	c = e.Config()
	c.Zones[0].RecordViews = []RecordView{{Clients: []string{"10.0.0.0/28"}, Records: []string{"new.home.arpa. 60 IN A 192.0.2.28"}}}
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	if zoneSOA(e.Config().Zones[0]).Serial != 3 {
		t.Fatal("split edit did not advance serial")
	}
	c = e.Config()
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	if zoneSOA(e.Config().Zones[0]).Serial != 3 {
		t.Fatal("unchanged zone advanced serial")
	}
}

func TestSignedMultiMessageAXFR(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	_, addr := transferPrimary(t, func(c *Config) {
		c.Zones[0].Transfer = ZoneTransfer{Allow: []string{"127.0.0.1/32"}, KeyName: "multi.", Secret: secret}
		for i := 0; i < 1600; i++ {
			c.Zones[0].Records = append(c.Zones[0].Records, fmt.Sprintf("record-%04d.home.arpa. 60 IN TXT \"%s\"", i, strings.Repeat("x", 100)))
		}
	})
	z, err := FetchSecondary(context.Background(), Zone{Name: "home.arpa.", Kind: "secondary", Servers: []string{"127.0.0.1:1", addr}, Transfer: ZoneTransfer{KeyName: "multi.", Secret: secret}})
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 1604 {
		t.Fatal(len(z.Records))
	}
}

func TestNewReplyProtocolAndOwnership(t *testing.T) {
	for _, opcode := range []int{dns.OpcodeQuery, dns.OpcodeNotify, dns.OpcodeUpdate} {
		for _, count := range []int{0, 1, 2} {
			q := new(dns.Msg)
			q.Id = 1234
			q.Opcode = opcode
			q.RecursionDesired = true
			q.CheckingDisabled = true
			q.AuthenticatedData = true
			q.Authoritative = true
			q.Question = []dns.Question{{Name: "Case.Example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "second.example.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}[:count]
			want := new(dns.Msg)
			want.SetReply(q)
			want.Rcode = dns.RcodeRefused
			want.RecursionAvailable = true
			got := newReply(q, dns.RcodeRefused)
			a, err := got.Pack()
			if err != nil {
				t.Fatal(err)
			}
			b, err := want.Pack()
			if err != nil || !bytes.Equal(a, b) {
				t.Fatalf("reply mismatch opcode=%d count=%d", opcode, count)
			}
			if count > 0 {
				got.Question[0].Name = "changed.example."
				if q.Question[0].Name != "Case.Example." {
					t.Fatal("question aliases request")
				}
			}
		}
	}
}
