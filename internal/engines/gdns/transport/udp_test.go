// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestUDPWorkerGroup(t *testing.T) {
	workers := 1
	if runtime.GOOS == "linux" {
		workers = 3
	}
	conns, err := ListenUDP("127.0.0.1:0", workers)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != workers {
		t.Fatal("wrong worker count")
	}
	servers := []*dns.Server{}
	for _, conn := range conns {
		if conn.LocalAddr().String() != conns[0].LocalAddr().String() {
			t.Fatal("workers bound different ports")
		}
		server := &dns.Server{PacketConn: conn, UDPSize: 1232, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { m := new(dns.Msg); m.SetReply(q); _ = w.WriteMsg(m) })}
		servers = append(servers, server)
		go func() { _ = server.ActivateAndServe() }()
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.ShutdownContext(ctx)
		}
	}()
	client := &dns.Client{Timeout: time.Second}
	for i := 0; i < 48; i++ {
		q := new(dns.Msg)
		q.SetQuestion("workers.invalid.", dns.TypeA)
		m, _, err := client.Exchange(q, conns[0].LocalAddr().String())
		if err != nil || m.Id != q.Id || m.Rcode != 0 {
			t.Fatal("worker reply", m, err)
		}
	}
}
func TestUDPBindFailureDoesNotTakeOverExistingListener(t *testing.T) {
	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	workers := 1
	if runtime.GOOS == "linux" {
		workers = 3
	}
	conns, err := ListenUDP(first.LocalAddr().String(), workers)
	if err == nil {
		for _, conn := range conns {
			conn.Close()
		}
		t.Fatal("took over an exclusive listener")
	}
	for _, n := range []int{-1, 65} {
		if _, err = ListenUDP("127.0.0.1:0", n); err == nil {
			t.Fatal("invalid worker count")
		}
	}
}
