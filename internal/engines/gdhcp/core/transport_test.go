// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"github.com/stretchr/testify/require"
)

func TestUDPReplyDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, ci, gi, want string
		flags              uint16
		port               int
	}{
		{name: "unconfigured client without broadcast flag", want: "255.255.255.255", port: 68},
		{name: "broadcast requested", flags: 0x8000, want: "255.255.255.255", port: 68},
		{name: "renewal", ci: "192.168.10.100", want: "192.168.10.100", port: 68},
		{name: "inform", ci: "192.168.10.101", want: "192.168.10.101", port: 68},
		{name: "relay takes precedence over ciaddr", ci: "192.168.30.100", gi: "10.0.0.1", want: "10.0.0.1", port: 67},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := discover("02:00:00:00:00:99", 1)
			p.Flags = tc.flags
			if tc.ci != "" {
				p.CIAddr = netip.MustParseAddr(tc.ci)
			}
			if tc.gi != "" {
				p.GIAddr = netip.MustParseAddr(tc.gi)
			}
			yi := netip.MustParseAddr("192.168.10.100")
			if tc.name == "inform" {
				yi = netip.Addr{}
			}
			dest := destination(p, yi)
			require.Equal(t, tc.want, dest.IP.String())
			require.Equal(t, tc.port, dest.Port)
		})
	}
}

func TestNAKIgnoresInvalidClientAddress(t *testing.T) {
	svc := newTestService(t, nil)
	for _, relayed := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "relay"}[relayed], func(t *testing.T) {
			p := discover("02:00:00:00:00:99", 1)
			p.CIAddr = netip.MustParseAddr("203.0.113.99")
			p.Flags = 0
			if relayed {
				p.GIAddr = netip.MustParseAddr("10.0.0.1")
			}
			out := svc.nak(svc.current(), p, "wrong subnet")
			require.Equal(t, dhcp.MsgNak, out.Packet.MessageType())
			require.True(t, out.Packet.CIAddr.IsUnspecified())
			require.False(t, out.Packet.SIAddr.IsValid())
			require.True(t, out.Packet.Broadcast())
			if relayed {
				require.Equal(t, "10.0.0.1", out.Dest.IP.String())
				require.Equal(t, 67, out.Dest.Port)
			} else {
				require.True(t, out.Dest.IP.Equal(net.IPv4bcast))
				require.Equal(t, 68, out.Dest.Port)
			}
			require.Equal(t, "203.0.113.99", p.CIAddr.String(), "request must not be mutated")
		})
	}
}

func TestIgnoreNonRequestWithoutAllocating(t *testing.T) {
	svc := newTestService(t, nil)
	for _, op := range []byte{0, dhcp.BootReply, 3, 255} {
		p := discover("02:00:00:00:00:99", 1)
		p.Op = op
		out, err := svc.Handle(context.Background(), Input{Packet: p, VLAN: pint(10)})
		require.NoError(t, err)
		require.Nil(t, out)
	}
	leases, err := svc.Store().ActiveLeases(context.Background(), svc.now())
	require.NoError(t, err)
	require.Empty(t, leases)
}

func TestExplicitVLANInterfaceMapping(t *testing.T) {
	svc := newTestService(t, nil)
	cfg := testConfig(t)
	cfg.VLANs[1].Interface = "voice0"
	require.NoError(t, svc.Apply(context.Background(), cfg))
	out, err := svc.Handle(context.Background(), Input{Packet: discover("02:00:00:00:00:99", 1), Iface: "voice0"})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, 20, *out.VLAN)
	require.True(t, netip.MustParsePrefix("192.168.20.0/24").Contains(out.Packet.YIAddr))
	// Explicit mappings take precedence over naming conventions.
	cfg.VLANs[1].Interface = "eth0.999"
	require.NoError(t, svc.Apply(context.Background(), cfg))
	vlan, ok := vlanFromIface(svc.current(), "eth0.999")
	require.True(t, ok)
	require.Equal(t, 20, vlan)
	cfg.Server.Interfaces = append(cfg.Server.Interfaces, config.Interface{Name: "access.999", Mode: "access", VLAN: 10})
	require.NoError(t, svc.Apply(context.Background(), cfg))
	vlan, ok = vlanFromIface(svc.current(), "access.999")
	require.True(t, ok)
	require.Equal(t, 10, vlan)
	vlan, ok = vlanFromIface(svc.current(), "eth0.998")
	require.True(t, ok)
	require.Equal(t, 998, vlan, "unknown VLAN must remain unknown")
}

func TestNAKUsesIngressVLANPriority(t *testing.T) {
	svc := newTestService(t, nil)
	p := discover("02:00:00:00:00:99", 1)
	p.Set(dhcp.OptMessageType, []byte{dhcp.MsgRequest})
	p.Append(dhcp.IPOption(dhcp.OptRequestedIP, netip.MustParseAddr("203.0.113.99")))
	out, err := svc.Handle(context.Background(), Input{Packet: p, Iface: "eth0.20"})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, dhcp.MsgNak, out.Packet.MessageType())
	require.Equal(t, 6, out.PCP)
	require.Equal(t, 20, *out.VLAN)
}
