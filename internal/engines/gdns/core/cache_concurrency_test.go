// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCachedEDNSRepliesArePrivate(t *testing.T) {
	c := DefaultConfig()
	c.DNSSECValidation = true
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	name := "cache-private.invalid."
	for _, do := range []bool{false, true} {
		for _, cd := range []bool{false, true} {
			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeA)
			m.Response = true
			m.AuthenticatedData = true
			a, _ := dns.NewRR(name + " 300 IN A 192.0.2.42")
			m.Answer = []dns.RR{a, &dns.RRSIG{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 300}, Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}}
			e.state.Load().cache.put(responseCacheKey(name, dns.TypeA, do, cd, nil), m)
		}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				do, cd := i%2 == 0, i%3 == 0
				q := query(name, dns.TypeA)
				q.CheckingDisabled = cd
				q.AuthenticatedData = true
				q.SetEdns0(4096, do)
				q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
				r, result := e.Resolve(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
				opt := r.IsEdns0()
				if result != "CACHE" || opt == nil || opt.UDPSize() != 1232 || opt.Do() != do || len(opt.Option) != 0 || r.CheckingDisabled != cd || r.AuthenticatedData == cd || r.Answer[0].(*dns.A).A.String() != "192.0.2.42" {
					t.Errorf("reply policy/isolation: worker=%d result=%s reply=%v", worker, result, r)
					return
				}
				if _, err := r.Pack(); err != nil {
					t.Error(err)
					return
				}
				// Mutating any returned object must not affect another worker or the request.
				r.Answer[0].(*dns.A).A[0] = 99
				r.Answer[0].Header().Ttl = 0
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "ff"})
				opt.SetUDPSize(512)
				if q.IsEdns0().UDPSize() != 4096 || len(q.IsEdns0().Option) != 1 {
					t.Error("request OPT modified")
					return
				}
			}
		}(worker)
	}
	wg.Wait()
}

func TestCachedEDNSStillRejectsInvalidSignatureTimes(t *testing.T) {
	for _, future := range []bool{false, true} {
		c := newCache(64)
		m := new(dns.Msg)
		m.AuthenticatedData = true
		a, _ := dns.NewRR("example. 300 IN A 192.0.2.1")
		start, end := time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
		if future {
			start, end = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
		}
		m.Answer = []dns.RR{a, &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 300}, Inception: uint32(start.Unix()), Expiration: uint32(end.Unix())}}
		c.put("secure", m)
		if c.getReply("secure", true) != nil {
			t.Fatal("invalid secure entry served", future)
		}
	}
}

func TestJournalConcurrentWritersSnapshotsAndResize(t *testing.T) {
	c := DefaultConfig()
	c.QueryLogLimit = 100
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var writers sync.WaitGroup
	done := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for iteration := 0; ; iteration++ {
			select {
			case <-done:
				return
			default:
			}
			if iteration%7 == 0 {
				e.resizeLogs(100 + iteration%200)
			}
			p := e.QueryLogs(1, 25, 0)
			for i, row := range p.Items {
				if row.ID != p.Anchor-uint64(i) || row.Result != "NOERROR" || row.Type != "A" {
					t.Errorf("incomplete journal snapshot: %+v anchor=%d", row, p.Anchor)
					return
				}
			}
			e.RecentLogs(8)
		}
	}()
	const workers, perWorker = 16, 2000
	for worker := 0; worker < workers; worker++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < perWorker; i++ {
				e.appendLog(logEntry{at: time.Now().UnixNano(), name: fmt.Sprintf("w%d-%d.example.", w, i), qtype: dns.TypeA, result: "NOERROR"})
			}
		}(worker)
	}
	writers.Wait()
	close(done)
	<-readerDone
	// A final grow may legitimately leave spare capacity. Fix retention at the
	// smallest exercised capacity before asserting every retained ID is present.
	e.resizeLogs(100)
	e.resizeLogs(200)
	for i := 0; i < 100; i++ {
		e.appendLog(logEntry{at: time.Now().UnixNano(), qtype: dns.TypeA, result: "NOERROR"})
	}
	p := e.QueryLogs(1, 100, 0)
	if p.Anchor != workers*perWorker+100 || p.Total != p.Capacity {
		t.Fatalf("journal lost retained events: %+v", p)
	}
	for page := 1; page <= p.Pages; page++ {
		r := e.QueryLogs(page, 100, p.Anchor)
		for i, row := range r.Items {
			if row.ID != p.Anchor-uint64((page-1)*100+i) {
				t.Fatal("gap in final journal", row.ID)
			}
		}
	}
}
