// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestZoneBoundaryFastPathMatchesDNSRules(t *testing.T) {
	names := []string{".", "example.", "a.example.", "a.badexample.", "EXAMPLE.", "a.ExAmPlE.", "b.a.example.", "a\\.example.", "a\\046example.", "a\\\\.example.", "é.example.", "É.example.", "*.example.", "example", ""}
	for _, parent := range names {
		for _, name := range names {
			if got, want := withinZone(parent, name), dns.IsSubDomain(parent, name); got != want {
				t.Fatalf("%q in %q: got %t want %t", name, parent, got, want)
			}
		}
	}
}
func TestJournalAnchorsAcrossWrapAndResize(t *testing.T) {
	c := DefaultConfig()
	c.QueryLogLimit = 100
	e, _ := New(c)
	random := rand.New(rand.NewPCG(1, 2))
	capacity := 100
	sequence := uint64(0)
	model := []uint64{}
	for step := 0; step < 1200; step++ {
		if step%71 == 0 {
			capacity = 100 + random.IntN(300)
			e.resizeLogs(capacity)
			if len(model) > capacity {
				model = model[len(model)-capacity:]
			}
		}
		sequence++
		e.appendLog(logEntry{at: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC).UnixNano(), client: netip.MustParseAddr("127.0.0.1"), name: fmt.Sprint(sequence), qtype: dns.TypeA, result: "NOERROR"})
		model = append(model, sequence)
		if len(model) > capacity {
			model = model[1:]
		}
		anchor := uint64(random.IntN(int(sequence) + 100))
		if anchor == 0 {
			anchor = sequence
		}
		eligible := []uint64{}
		for i := len(model) - 1; i >= 0; i-- {
			if model[i] <= anchor {
				eligible = append(eligible, model[i])
			}
		}
		size := 1 + random.IntN(100)
		page := 1 + random.IntN(30)
		pages := max(1, (len(eligible)+size-1)/size)
		page = min(page, pages)
		got := e.QueryLogs(page, size, anchor)
		if got.Total != len(eligible) || got.Pages != pages || got.Page != page || got.Capacity != capacity {
			t.Fatalf("metadata: %+v eligible=%d", got, len(eligible))
		}
		start := (page - 1) * size
		end := min(start+size, len(eligible))
		want := eligible[start:end]
		if len(got.Items) != len(want) {
			t.Fatal("page length")
		}
		for i, row := range got.Items {
			if row.ID != want[i] || row.Time != "2026-11-05T00:00:00Z" || row.Client != "127.0.0.1" || row.Type != "A" {
				t.Fatal("page content", row, want)
			}
		}
	}
}
func TestMissHonorsCallerDeadlineAfterFastPathOptimization(t *testing.T) {
	server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		time.Sleep(100 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		_ = w.WriteMsg(m)
	})
	c := DefaultConfig()
	c.Mode = "forward"
	c.Upstreams = []string{server}
	e, _ := New(c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	start := time.Now()
	m := e.AnswerAs(ctx, query("deadline.invalid.", dns.TypeA), netip.MustParseAddr("127.0.0.1"), "udp")
	if m.Rcode != dns.RcodeServerFailure || time.Since(start) > 80*time.Millisecond {
		t.Fatal("upstream miss ignored caller deadline", m)
	}
}

func TestClientIPPreservesActualPeer(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:192.0.2.3", "fe80::1%eth0"} {
		addr := netip.MustParseAddr(ip)
		udp := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 12345))
		tcp := net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 12345))
		for _, peer := range []net.Addr{udp, tcp} {
			if got := ClientIP(peer); got != addr.Unmap() {
				t.Fatal("peer changed", peer, got)
			}
		}
	}
	if ClientIP(nil).IsValid() {
		t.Fatal("nil peer accepted")
	}
}

func FuzzZoneBoundaryMatchesDNS(f *testing.F) {
	for _, seed := range [][2]string{{"example.", "a.example."}, {"EXAMPLE.", "A.example."}, {"example.", "a\\.example."}, {".", "é.example."}, {"b.example.", "ab.example."}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, parent, name string) {
		if len(parent) > 255 || len(name) > 255 {
			return
		}
		if _, ok := dns.IsDomainName(parent); !ok {
			return
		}
		if _, ok := dns.IsDomainName(name); !ok {
			return
		}
		if got, want := withinZone(parent, name), dns.IsSubDomain(parent, name); got != want {
			t.Fatalf("%q in %q: %t != %t", name, parent, got, want)
		}
	})
}
