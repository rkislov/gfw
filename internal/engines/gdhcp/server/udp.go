// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"log/slog"
	"net"
	"syscall"

	"github.com/rkislov/gfw/internal/engines/gdhcp/core"
	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"golang.org/x/net/ipv4"
)

// Listener owns a bound DHCP UDP socket.
type Listener struct {
	conn     *net.UDPConn
	pc       *ipv4.PacketConn
	control  bool
	priority int
}

// Listen binds before the process reports readiness to its service manager.
func Listen(addr string) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err == nil {
		var optionErr error
		err = raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		if err == nil {
			err = optionErr
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetReadBuffer(4 << 20)
	pc := ipv4.NewPacketConn(conn)
	control := pc.SetControlMessage(ipv4.FlagInterface, true) == nil
	return &Listener{conn: conn, pc: pc, control: control}, nil
}

func (l *Listener) Close() error { return l.conn.Close() }

// Serve reads DHCPv4 datagrams until ctx is cancelled.
func Serve(ctx context.Context, addr string, svc *core.Service, log *slog.Logger) error {
	l, err := Listen(addr)
	if err != nil {
		return err
	}
	return l.Serve(ctx, svc, log)
}

func (l *Listener) Serve(ctx context.Context, svc *core.Service, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	defer l.Close()
	conn, pc, control := l.conn, l.pc, l.control
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	// Keep receiving while the previous group commits to SQLite. Only packets
	// already in the bounded queue are batched; there is no low-rate delay.
	incoming := make(chan datagram, 256)
	go func() {
		defer close(incoming)
		buf := make([]byte, 4096)
		for {
			n, cm, src, err := readPacket(pc, conn, buf, control)
			d := datagram{cm: cm, src: src, err: err}
			if err == nil {
				d.raw = append([]byte(nil), buf[:n]...)
			}
			select {
			case incoming <- d:
			case <-done:
				return
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		var first datagram
		select {
		case <-ctx.Done():
			return nil
		case d, ok := <-incoming:
			if !ok {
				return nil
			}
			first = d
		}
		group := []datagram{first}
	drain:
		for len(group) < 64 {
			select {
			case d, ok := <-incoming:
				if !ok {
					break drain
				}
				group = append(group, d)
			default:
				break drain
			}
		}
		inputs := make([]core.Input, 0, len(group))
		transport := make([]datagram, 0, len(group))
		for _, d := range group {
			if d.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return d.err
			}
			pkt, err := dhcp.Parse(d.raw)
			if err != nil {
				log.Debug("dhcp parse", "err", err, "from", d.src)
				continue
			}
			iface := ""
			if d.cm != nil && d.cm.IfIndex != 0 {
				if name, err := interfaceName(conn, d.cm.IfIndex); err == nil {
					iface = name
				}
			}
			inputs = append(inputs, core.Input{Packet: pkt, Iface: iface})
			transport = append(transport, d)
		}
		outputs, err := svc.HandleBatch(ctx, inputs)
		if err != nil {
			log.Error("dhcp handle batch", "err", err, "size", len(inputs))
			continue
		}
		for i, out := range outputs {
			if out == nil || out.Packet == nil || out.Dest == nil {
				continue
			}
			raw, err := out.Packet.Marshal()
			if err != nil {
				log.Error("dhcp marshal", "err", err)
				continue
			}
			if out.PCP != l.priority {
				if err := setPriority(conn, out.PCP); err != nil {
					log.Error("dhcp priority", "err", err, "pcp", out.PCP, "interface", inputs[i].Iface)
					continue
				}
				l.priority = out.PCP
			}
			cm := transport[i].cm
			if control && cm != nil {
				_, err = pc.WriteTo(raw, &ipv4.ControlMessage{IfIndex: cm.IfIndex}, out.Dest)
			} else {
				_, err = conn.WriteTo(raw, out.Dest)
			}
			if err != nil {
				log.Error("dhcp send", "err", err, "to", out.Dest, "interface", inputs[i].Iface)
			}
		}
	}
}

type datagram struct {
	raw []byte
	cm  *ipv4.ControlMessage
	src net.Addr
	err error
}

func readPacket(pc *ipv4.PacketConn, conn *net.UDPConn, buf []byte, control bool) (int, *ipv4.ControlMessage, net.Addr, error) {
	if control {
		n, cm, src, err := pc.ReadFrom(buf)
		return n, cm, src, err
	}
	n, src, err := conn.ReadFrom(buf)
	return n, nil, src, err
}
