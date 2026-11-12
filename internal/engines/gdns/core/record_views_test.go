// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net/netip"
	"testing"
)

func TestRecordViewsInsideOneZone(t *testing.T) {
	c := DefaultConfig()
	c.AllowedClients = append(c.AllowedClients, "2001:db8::/32")
	z := zone("example.", "192.0.2.1")
	z.Records = append(z.Records, "host.example. 60 IN AAAA 2001:db8::1", "shared.example. 60 IN TXT \"common\"")
	z.RecordViews = []RecordView{{Clients: []string{"10.0.0.0/8"}, Records: []string{"host.example. 60 IN A 10.0.0.1", "private.example. 60 IN A 10.0.0.2"}}, {Clients: []string{"10.1.0.0/16"}, Records: []string{"host.example. 60 IN A 10.1.0.1", "host.example. 60 IN TXT \"narrow\""}}, {Clients: []string{"2001:db8::/32"}, Records: []string{"host.example. 60 IN A 192.0.2.6"}}}
	c.Zones = []Zone{z}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ client, want string }{{"127.0.0.1", "192.0.2.1"}, {"10.2.0.1", "10.0.0.1"}, {"10.1.2.3", "10.1.0.1"}, {"2001:db8::2", "192.0.2.6"}} {
		ip := netip.MustParseAddr(tc.client)
		r, _ := e.Resolve(context.Background(), query("host.example.", dns.TypeA), ip)
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != tc.want {
			t.Fatalf("%s: %v", tc.client, r)
		}
		r, _ = e.Resolve(context.Background(), query("host.example.", dns.TypeAAAA), ip)
		if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::1" {
			t.Fatal("common RRset not inherited", r)
		}
		r, _ = e.Resolve(context.Background(), query("shared.example.", dns.TypeTXT), ip)
		if len(r.Answer) != 1 {
			t.Fatal("unrelated records lost", r)
		}
	}
	r, _ := e.Resolve(context.Background(), query("private.example.", dns.TypeA), netip.MustParseAddr("127.0.0.1"))
	if r.Rcode != dns.RcodeNameError {
		t.Fatal("private owner leaked", r)
	}
	r, _ = e.Resolve(context.Background(), query("private.example.", dns.TypeAAAA), netip.MustParseAddr("10.1.2.3"))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatal("private empty type must be NODATA", r)
	}
	copy := e.Config()
	copy.Zones[0].RecordViews[0].Records[0] = "corrupt"
	if e.Config().Zones[0].RecordViews[0].Records[0] == "corrupt" {
		t.Fatal("record views are mutable")
	}
}
func TestRecordViewCNAMEAndWildcard(t *testing.T) {
	c := DefaultConfig()
	z := zone("example.", "192.0.2.1")
	z.Records = append(z.Records, "*.example. 60 IN A 192.0.2.8")
	z.RecordViews = []RecordView{{Clients: []string{"10.0.0.0/8"}, Records: []string{"host.example. 60 IN CNAME target.example.", "leaf.branch.example. 60 IN A 10.0.0.1"}}, {Clients: []string{"10.1.0.0/16"}, Records: []string{"host.example. 60 IN A 10.1.0.1"}}}
	c.Zones = []Zone{z}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip  string
		typ uint16
	}{{"10.2.0.1", dns.TypeCNAME}, {"10.1.0.1", dns.TypeA}} {
		r, _ := e.Resolve(context.Background(), query("host.example.", dns.TypeA), netip.MustParseAddr(tc.ip))
		if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != tc.typ {
			t.Fatal(r)
		}
	}
	// A private empty nonterminal suppresses the broad wildcard only for its clients.
	r, _ := e.Resolve(context.Background(), query("none.branch.example.", dns.TypeA), netip.MustParseAddr("10.0.0.1"))
	if r.Rcode != dns.RcodeNameError {
		t.Fatal(r)
	}
	r, _ = e.Resolve(context.Background(), query("none.branch.example.", dns.TypeA), netip.MustParseAddr("127.0.0.1"))
	if len(r.Answer) != 1 {
		t.Fatal("private node altered public wildcard", r)
	}
	z.RecordViews = append(z.RecordViews, RecordView{Clients: []string{"10.0.0.0/8"}, Records: []string{"host.example. 60 IN A 10.0.0.9"}})
	c.Zones = []Zone{z}
	if _, err = New(c); err == nil {
		t.Fatal("conflicting CNAME view accepted")
	}
}
func TestJournalPaginationAndResize(t *testing.T) {
	c := DefaultConfig()
	c.QueryLogLimit = 100
	e, _ := New(c)
	for i := 0; i < 150; i++ {
		e.log(QueryLog{Name: fmt.Sprintf("d%d.example.", i)})
	}
	first := e.QueryLogs(1, 10, 0)
	if first.Total != 100 || first.Items[0].ID != 150 || first.Pages != 10 {
		t.Fatalf("%+v", first)
	}
	for i := 0; i < 10; i++ {
		e.log(QueryLog{Name: "new.example."})
	}
	second := e.QueryLogs(2, 10, first.Anchor)
	if second.Items[0].ID != 140 || second.Items[9].ID != 131 {
		t.Fatal("incoming logs shifted pinned pages", second)
	}
	c.QueryLogLimit = 200
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	e.log(QueryLog{Name: "after-resize.example."})
	logs := e.RecentLogs(101)
	if len(logs) != 101 || logs[0].ID != 161 || logs[1].ID != 160 || logs[100].ID != 61 {
		t.Fatal("growing log broke chronological order")
	}
	c.QueryLogLimit = 100
	_ = e.Apply(c)
	logs = e.Logs()
	if len(logs) != 100 || logs[99].ID != 62 {
		t.Fatal("shrinking log lost newest records")
	}
}

func TestRecordViewSlash28Boundaries(t *testing.T) {
	c := DefaultConfig()
	z := zone("example.", "192.0.2.1")
	z.RecordViews = []RecordView{{Clients: []string{"10.1.2.0/24"}, Records: []string{"host.example. 60 IN A 10.1.2.1"}}, {Clients: []string{"10.1.2.16/28"}, Records: []string{"host.example. 60 IN A 10.1.2.17"}}, {Clients: []string{"10.1.2.20/32"}, Records: []string{"host.example. 60 IN A 10.1.2.99"}}}
	c.Zones = []Zone{z}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ client, want string }{{"10.1.2.15", "10.1.2.1"}, {"10.1.2.16", "10.1.2.17"}, {"10.1.2.19", "10.1.2.17"}, {"10.1.2.20", "10.1.2.99"}, {"10.1.2.31", "10.1.2.17"}, {"10.1.2.32", "10.1.2.1"}, {"10.1.3.1", "192.0.2.1"}} {
		r, _ := e.Resolve(context.Background(), query("host.example.", dns.TypeA), netip.MustParseAddr(tc.client))
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != tc.want {
			t.Fatalf("%s outside expected prefix: %v", tc.client, r)
		}
	}
}
