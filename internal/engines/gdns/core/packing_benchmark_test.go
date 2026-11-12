// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"github.com/miekg/dns"
	"sync"
	"testing"
)

type packingBuffer struct{ data [4096]byte }

var packingPool = sync.Pool{New: func() any { return new(packingBuffer) }}

func BenchmarkResponsePacking(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("router.home.arpa.", dns.TypeA)
	m.Response = true
	m.SetEdns0(1232, true)
	rr, _ := dns.NewRR("router.home.arpa. 300 IN A 192.168.1.1")
	m.Answer = []dns.RR{rr}
	b.Run("allocate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := m.Pack(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := packingPool.Get().(*packingBuffer)
			_, err := m.PackBuffer(buf.data[:])
			packingPool.Put(buf)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
