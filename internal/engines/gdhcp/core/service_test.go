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

package core

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"github.com/rkislov/gfw/internal/engines/gdhcp/logbuf"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
)

func TestScenarios(t *testing.T) {
	ctx := context.Background()
	buf := logbuf.New(200)
	logger := slog.New(logbuf.NewHandler(slog.NewTextHandler(io.Discard, nil), buf))
	svc := newTestService(t, logger)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("local vlan 10", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:10", 1)
		out, err := svc.Handle(ctx, Input{Packet: disc, Iface: "eth0.10"})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, dhcp.MsgOffer, out.Packet.MessageType())
		require.Equal(t, 5, out.PCP)
		require.Equal(t, 10, *out.VLAN)
		ip := out.Packet.YIAddr
		require.True(t, ip.Compare(netip.MustParseAddr("192.168.10.100")) >= 0)
		require.True(t, ip.Compare(netip.MustParseAddr("192.168.10.200")) <= 0)

		req := discover("02:00:00:00:00:10", 1)
		req.Set(dhcp.OptMessageType, []byte{dhcp.MsgRequest})
		yb := ip.As4()
		sid := netip.MustParseAddr("192.168.10.1").As4()
		req.Set(dhcp.OptRequestedIP, yb[:])
		req.Set(dhcp.OptServerID, sid[:])
		ack, err := svc.Handle(ctx, Input{Packet: req, Iface: "eth0.10"})
		require.NoError(t, err)
		require.Equal(t, dhcp.MsgAck, ack.Packet.MessageType())
		require.Equal(t, ip, ack.Packet.YIAddr)
		lease, err := svc.Store().GetLease(ctx, ip.String())
		require.NoError(t, err)
		require.Equal(t, model.StateBound, lease.State)
	})

	t.Run("reservation", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("aa:bb:cc:dd:ee:ff", 2)
		out, err := svc.Handle(ctx, Input{Packet: disc, VLAN: pint(10)})
		require.NoError(t, err)
		require.Equal(t, "192.168.10.50", out.Packet.YIAddr.String())
		require.Equal(t, "printer-01", out.Packet.Hostname())
	})

	t.Run("voip options and pcp", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:20", 3)
		out, err := svc.Handle(ctx, Input{Packet: disc, VLAN: pint(20)})
		require.NoError(t, err)
		require.Equal(t, 6, out.PCP)
		raw, ok := out.Packet.Get(dhcp.OptTFTPServer)
		require.True(t, ok)
		require.Equal(t, "tftp.voip.local", string(raw))
		opt43, ok := out.Packet.Get(dhcp.OptVendorSpecific)
		require.True(t, ok)
		require.Equal(t, "vlan-id=20;l2-priority=6", string(opt43))
	})

	t.Run("cisco relay echoes option 82", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:21", 4)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 1
		raw := append(dhcpOpt82(1, []byte("Gi0/1:vlan20")), dhcpOpt82(2, []byte("relay-01"))...)
		disc.Add(dhcp.OptRelayAgent, raw)
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, 20, *out.VLAN)
		require.True(t, out.Packet.YIAddr.Compare(netip.MustParseAddr("192.168.20.10")) >= 0)
		got := out.Packet.RelayAgentBlobs()
		require.Len(t, got, 1)
		require.True(t, bytes.Equal(raw, got[0]))
		require.Equal(t, 67, out.Dest.Port)
		require.Equal(t, "10.0.0.1", out.Dest.IP.String())
	})

	t.Run("huawei circuit id", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:30", 5)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 1
		body := append(dhcpOpt82(1, []byte("slot=0;subslot=0;GE0/0/1;vlanid=30")), dhcpOpt82(2, []byte("relay-01"))...)
		disc.Add(dhcp.OptRelayAgent, body)
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.Equal(t, 30, *out.VLAN)
		require.True(t, out.Packet.YIAddr.Compare(netip.MustParseAddr("192.168.30.10")) >= 0)
	})

	t.Run("link selection beats giaddr", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:22", 6)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 1
		link := netip.MustParseAddr("192.168.20.1").As4()
		body := append(dhcpOpt82(2, []byte("relay-01")), dhcpOpt82(5, link[:])...)
		disc.Add(dhcp.OptRelayAgent, body)
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.Equal(t, 20, *out.VLAN)
	})

	t.Run("broken circuit falls back to default pool", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:11", 7)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 1
		body := append(dhcpOpt82(1, []byte("not-a-circuit")), dhcpOpt82(2, []byte("relay-01"))...)
		disc.Add(dhcp.OptRelayAgent, body)
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, 10, *out.VLAN)
	})

	t.Run("untrusted relay", func(t *testing.T) {
		disc := discover("02:00:00:00:00:99", 8)
		disc.GIAddr = netip.MustParseAddr("10.9.9.9")
		disc.Hops = 1
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.Nil(t, out)
		require.Contains(t, join(buf.Recent()), "untrusted")
	})

	t.Run("hops exceeded", func(t *testing.T) {
		disc := discover("02:00:00:00:00:98", 9)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 5
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.Nil(t, out)
	})

	t.Run("multi-hop uses nearest circuit", func(t *testing.T) {
		svc.now = func() time.Time { return now }
		disc := discover("02:00:00:00:00:23", 10)
		disc.GIAddr = netip.MustParseAddr("10.0.0.1")
		disc.Hops = 2
		inner := append(dhcpOpt82(1, []byte("bridge:30")), dhcpOpt82(2, []byte("relay-inner"))...)
		outer := append(dhcpOpt82(1, []byte("Gi0/1:vlan20")), dhcpOpt82(2, []byte("relay-01"))...)
		outer = append(outer, dhcpOpt82(152, inner)...)
		disc.Add(dhcp.OptRelayAgent, outer)
		out, err := svc.Handle(ctx, Input{Packet: disc})
		require.NoError(t, err)
		require.Equal(t, 20, *out.VLAN)
		require.True(t, bytes.Equal(outer, out.Packet.RelayAgentBlobs()[0]))
	})

	t.Run("authoritative nak", func(t *testing.T) {
		req := discover("02:00:00:00:00:77", 11)
		req.Set(dhcp.OptMessageType, []byte{dhcp.MsgRequest})
		bad := netip.MustParseAddr("10.9.9.9").As4()
		sid := netip.MustParseAddr("192.168.10.1").As4()
		req.Set(dhcp.OptRequestedIP, bad[:])
		req.Set(dhcp.OptServerID, sid[:])
		out, err := svc.Handle(ctx, Input{Packet: req, VLAN: pint(10)})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, dhcp.MsgNak, out.Packet.MessageType())
	})
}

func TestParallelUnique(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var mu sync.Mutex
	seen := map[string]struct{}{}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mac := net.HardwareAddr{0x02, 0x10, 0, 0, byte(i >> 8), byte(i)}
			pkt := dhcp.NewRequest(dhcp.MsgDiscover, mac, uint32(1000+i))
			out, err := svc.Handle(ctx, Input{Packet: pkt, VLAN: pint(10)})
			require.NoError(t, err)
			require.NotNil(t, out)
			mu.Lock()
			defer mu.Unlock()
			ip := out.Packet.YIAddr.String()
			_, dup := seen[ip]
			require.False(t, dup, ip)
			seen[ip] = struct{}{}
		}(i)
	}
	wg.Wait()
	require.Len(t, seen, 40)
}

func TestReloadAndPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "leases.db")
	cfg := testConfig(t)
	cfg.Database.DSN = dsn
	store, err := storage.Open(ctx, "sqlite", dsn)
	require.NoError(t, err)
	svc, err := New(ctx, Options{Store: store, Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	require.NoError(t, err)
	disc := discover("02:00:00:00:00:40", 40)
	out, err := svc.Handle(ctx, Input{Packet: disc, VLAN: pint(10)})
	require.NoError(t, err)
	ip := out.Packet.YIAddr.String()

	cfg.Server.Hostname = "reloaded"
	require.NoError(t, svc.Apply(ctx, cfg))
	again, err := svc.Handle(ctx, Input{Packet: discover("02:00:00:00:00:41", 41), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, again)
	require.NotEqual(t, ip, again.Packet.YIAddr.String())

	require.NoError(t, store.Close())
	store2, err := storage.Open(ctx, "sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	lease, err := store2.GetLease(ctx, ip)
	require.NoError(t, err)
	require.Equal(t, "02:00:00:00:00:40", lease.MAC)
	svc2, err := New(ctx, Options{Store: store2, Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	require.NoError(t, err)
	reoffer, err := svc2.Handle(ctx, Input{Packet: discover("02:00:00:00:00:40", 42), VLAN: pint(10)})
	require.NoError(t, err)
	require.Equal(t, ip, reoffer.Packet.YIAddr.String())
}

func newTestService(t *testing.T, logger *slog.Logger) *Service {
	t.Helper()
	ctx := context.Background()
	cfg := testConfig(t)
	dir := t.TempDir()
	dsn := filepath.Join(dir, "leases.db")
	cfg.Database.DSN = dsn
	store, err := storage.Open(ctx, "sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	svc, err := New(ctx, Options{Store: store, Config: cfg, Logger: logger})
	require.NoError(t, err)
	return svc
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	raw := []byte(`
server:
  interfaces:
    - name: eth0
      mode: trunk
      vlans: [10, 20, 30]
  authoritative: true
  ping_check: false
  lease_default: 1h
  lease_max: 2h
  server_id: 192.168.10.1
database:
  driver: sqlite
  dsn: /tmp/godhcp-test.db
api:
  listen: ":0"
  auth:
    jwt_secret: "dev-secret-dev-secret-dev-secret"
vlans:
  - id: 10
    name: office
    interface: eth0.10
    priority: 5
    subnet_ref: office-lan
  - id: 20
    name: voip
    interface: eth0.20
    priority: 6
    subnet_ref: voip-phones
    options:
      66: tftp.voip.local
      43: "vlan-id=20;l2-priority=6"
  - id: 30
    name: guest
    source: relay
    subnet_ref: guest-wifi
subnets:
  - id: office-lan
    network: 192.168.10.0/24
    range: [192.168.10.100, 192.168.10.200]
    gateway: 192.168.10.1
    dns: [1.1.1.1, 8.8.8.8]
    domain: lan.local
    vlan: 10
    reservations:
      - mac: "aa:bb:cc:dd:ee:ff"
        ip: 192.168.10.50
        hostname: printer-01
  - id: voip-phones
    network: 192.168.20.0/24
    range: [192.168.20.10, 192.168.20.80]
    gateway: 192.168.20.1
    vlan: 20
  - id: guest-wifi
    network: 192.168.30.0/24
    range: [192.168.30.10, 192.168.30.80]
    gateway: 192.168.30.1
    vlan: 30
relay:
  enabled: true
  max_relay_hops: 4
  unknown_vlan_action: default-pool
  default_pool: office-lan
  trusted_relays:
    - remote_id: relay-01
      giaddr: 10.0.0.1
logging:
  level: info
  format: json
`)
	cfg, err := config.Parse(raw, "test.yml")
	require.NoError(t, err)
	return cfg
}

func discover(mac string, xid uint32) *dhcp.Packet {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return dhcp.NewRequest(dhcp.MsgDiscover, hw, xid)
}

func dhcpOpt82(code byte, data []byte) []byte {
	b := make([]byte, 2+len(data))
	b[0] = code
	b[1] = byte(len(data))
	copy(b[2:], data)
	return b
}

func pint(v int) *int { return &v }

func join(lines []string) string {
	return string(bytes.Join(func() [][]byte {
		out := make([][]byte, len(lines))
		for i, l := range lines {
			out[i] = []byte(l)
		}
		return out
	}(), []byte("\n")))
}
