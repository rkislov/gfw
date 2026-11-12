// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"encoding/binary"
	"github.com/miekg/dns"
	"io"
	"net"
	"testing"
	"time"
)

// The client sends prepacked requests and reads raw answers. Profiles include
// both ends of loopback and therefore are not remote-client capacity claims.
func BenchmarkNetworkDNS(b *testing.B) {
	for _, network := range []string{"udp", "tcp"} {
		b.Run(network, func(b *testing.B) {
			c := DefaultConfig()
			c.QueryLog = false
			e, err := New(c)
			if err != nil {
				b.Fatal(err)
			}
			s := &dns.Server{Handler: e, TsigProvider: e, UDPSize: 1232, MaxTCPQueries: -1}
			var addr string
			if network == "udp" {
				p, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				s.PacketConn = p
				addr = p.LocalAddr().String()
			} else {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					b.Fatal(err)
				}
				s.Listener = l
				addr = l.Addr().String()
			}
			ready := make(chan struct{})
			s.NotifyStartedFunc = func() { close(ready) }
			go s.ActivateAndServe()
			<-ready
			b.Cleanup(func() { s.Shutdown() })
			q := query("router.home.arpa.", dns.TypeA)
			q.SetEdns0(1232, true)
			raw, _ := q.Pack()
			if network == "tcp" {
				header := []byte{0, 0}
				binary.BigEndian.PutUint16(header, uint16(len(raw)))
				raw = append(header, raw...)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				conn, err := net.Dial(network, addr)
				if err != nil {
					b.Error(err)
					return
				}
				defer conn.Close()
				buf := make([]byte, 65535)
				for pb.Next() {
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err = conn.Write(raw); err != nil {
						b.Error(err)
						return
					}
					if network == "tcp" {
						if _, err = io.ReadFull(conn, buf[:2]); err == nil {
							n := binary.BigEndian.Uint16(buf[:2])
							_, err = io.ReadFull(conn, buf[:n])
						}
					} else {
						_, err = conn.Read(buf)
					}
					if err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}
