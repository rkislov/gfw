// Copyright 2026 Кислов Роман Сергеевич
// Licensed under the Apache License, Version 2.0.

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
)

// Fail writes while leaving reads available, as with a read-only database.
type failingLeaseStore struct {
	storage.Store
	err error
}

func (s *failingLeaseStore) UpsertLease(ctx context.Context, l model.Lease) error {
	if s.err != nil {
		return s.err
	}
	return s.Store.UpsertLease(ctx, l)
}

func safetyService(t *testing.T) *Service {
	t.Helper()
	return newTestService(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func leasePacket(mac string, mt byte, ip netip.Addr) *dhcp.Packet {
	p := discover(mac, 123)
	p.Set(dhcp.OptMessageType, []byte{mt})
	if ip.IsValid() {
		if mt == dhcp.MsgRelease {
			p.CIAddr = ip
		} else {
			p.Append(dhcp.IPOption(dhcp.OptRequestedIP, ip))
		}
	}
	return p
}

func bindSafetyLease(t *testing.T, s *Service, mac string) model.Lease {
	t.Helper()
	ctx := context.Background()
	out, err := s.Handle(ctx, Input{Packet: discover(mac, 1), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, out)
	out, err = s.Handle(ctx, Input{Packet: leasePacket(mac, dhcp.MsgRequest, out.Packet.YIAddr), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, dhcp.MsgAck, out.Packet.MessageType())
	l, err := s.Store().GetLease(ctx, out.Packet.YIAddr.String())
	require.NoError(t, err)
	return l
}

func TestLeaseWriteFailureSuppressesReply(t *testing.T) {
	for _, mt := range []byte{dhcp.MsgDiscover, dhcp.MsgRequest} {
		t.Run(dhcp.MessageName(mt), func(t *testing.T) {
			s := safetyService(t)
			ctx := context.Background()
			diskErr := errors.New("disk unavailable")
			store := &failingLeaseStore{Store: s.store, err: diskErr}
			s.store = store
			called := make(chan model.Lease, 1)
			s.onBound = func(l model.Lease) { called <- l }
			ip := netip.MustParseAddr("192.168.10.100")
			out, err := s.Handle(ctx, Input{Packet: leasePacket("02:00:00:aa:00:01", mt, ip), VLAN: pint(10)})
			require.ErrorIs(t, err, diskErr)
			require.Nil(t, out)
			select {
			case <-called:
				t.Fatal("bound callback ran after failed persistence")
			default:
			}
			_, err = store.GetLease(ctx, ip.String())
			require.ErrorIs(t, err, storage.ErrNotFound)
			// Recovery may reuse an unannounced address, but must commit first.
			store.err = nil
			out, err = s.Handle(ctx, Input{Packet: leasePacket("02:00:00:aa:00:02", mt, ip), VLAN: pint(10)})
			require.NoError(t, err)
			require.NotNil(t, out)
			l, err := store.GetLease(ctx, ip.String())
			require.NoError(t, err)
			require.Equal(t, "02:00:00:aa:00:02", l.MAC)
		})
	}
}

func TestClosedDatabaseNeverOffersOrAcknowledges(t *testing.T) {
	s := safetyService(t)
	require.NoError(t, s.store.Close())
	for _, mt := range []byte{dhcp.MsgDiscover, dhcp.MsgRequest} {
		out, err := s.Handle(context.Background(), Input{Packet: leasePacket("02:00:00:aa:00:01", mt, netip.MustParseAddr("192.168.10.100")), VLAN: pint(10)})
		require.Error(t, err)
		require.Nil(t, out)
	}
}

func TestRequestCannotEscapeIngressVLAN(t *testing.T) {
	for _, authoritative := range []bool{true, false} {
		for _, iface := range []string{"explicit VLAN", "eth0.10", "eth0.999"} {
			t.Run(fmt.Sprintf("%s/authoritative=%t", iface, authoritative), func(t *testing.T) {
				s := safetyService(t)
				cfg := testConfig(t)
				cfg.Server.Authoritative = authoritative
				cfg.Relay.UnknownVLANAction = "ignore"
				require.NoError(t, s.Apply(context.Background(), cfg))
				ip := netip.MustParseAddr("192.168.20.40")
				in := Input{Packet: leasePacket("02:00:00:aa:00:03", dhcp.MsgRequest, ip), Iface: iface}
				if iface == "explicit VLAN" {
					in.VLAN = pint(10)
				}
				out, err := s.Handle(context.Background(), in)
				require.NoError(t, err)
				if authoritative && iface != "eth0.999" {
					require.NotNil(t, out)
					require.Equal(t, dhcp.MsgNak, out.Packet.MessageType())
				} else {
					require.Nil(t, out)
				}
				_, err = s.store.GetLease(context.Background(), ip.String())
				require.ErrorIs(t, err, storage.ErrNotFound)
			})
		}
	}
}

func TestLeaseControlRequiresOwner(t *testing.T) {
	for _, mt := range []byte{dhcp.MsgRelease, dhcp.MsgDecline} {
		for _, invalid := range []string{"MAC", "client-id", "subnet", "server-id", "expired", "unknown IP"} {
			t.Run(dhcp.MessageName(mt)+"/"+invalid, func(t *testing.T) {
				s := safetyService(t)
				ctx := context.Background()
				l := bindSafetyLease(t, s, "02:00:00:aa:00:04")
				p := leasePacket(l.MAC, mt, netip.MustParseAddr(l.IP))
				vlan := 10
				switch invalid {
				case "MAC":
					p = leasePacket("02:00:00:aa:00:05", mt, netip.MustParseAddr(l.IP))
				case "client-id":
					l.ClientID = "010203"
					require.NoError(t, s.store.UpsertLease(ctx, l))
					p.Append(dhcp.Option{Code: dhcp.OptClientID, Data: []byte{1, 2, 4}})
				case "subnet":
					vlan = 20
				case "server-id":
					p.Append(dhcp.IPOption(dhcp.OptServerID, netip.MustParseAddr("192.168.10.2")))
				case "expired":
					s.now = func() time.Time { return l.ExpiresAt.Add(time.Second) }
				case "unknown IP":
					p = leasePacket(l.MAC, mt, netip.MustParseAddr("192.168.10.199"))
				}
				out, err := s.Handle(ctx, Input{Packet: p, VLAN: pint(vlan)})
				require.NoError(t, err)
				require.Nil(t, out)
				after, err := s.store.GetLease(ctx, l.IP)
				require.NoError(t, err)
				require.Equal(t, l, after)
				_, err = s.store.GetLease(ctx, "192.168.10.199")
				require.ErrorIs(t, err, storage.ErrNotFound)
			})
		}
	}
}

func TestLeaseControlCommitBeforePoolChange(t *testing.T) {
	for _, mt := range []byte{dhcp.MsgRelease, dhcp.MsgDecline} {
		t.Run(dhcp.MessageName(mt), func(t *testing.T) {
			s := safetyService(t)
			ctx := context.Background()
			l := bindSafetyLease(t, s, "02:00:00:aa:00:04")
			diskErr := errors.New("read-only database")
			store := &failingLeaseStore{Store: s.store, err: diskErr}
			s.store = store
			p := leasePacket(l.MAC, mt, netip.MustParseAddr(l.IP))
			out, err := s.Handle(ctx, Input{Packet: p, VLAN: pint(10)})
			require.ErrorIs(t, err, diskErr)
			require.Nil(t, out)
			after, err := store.GetLease(ctx, l.IP)
			require.NoError(t, err)
			require.Equal(t, l, after)
			require.True(t, s.pools.Holds(l.SubnetID, "other", netip.MustParseAddr(l.IP)))
			store.err = nil
			_, err = s.Handle(ctx, Input{Packet: p, VLAN: pint(10)})
			require.NoError(t, err)
			after, err = store.GetLease(ctx, l.IP)
			require.NoError(t, err)
			if mt == dhcp.MsgRelease {
				require.Equal(t, model.StateReleased, after.State)
				require.False(t, s.pools.Holds(l.SubnetID, "other", netip.MustParseAddr(l.IP)))
			} else {
				require.Equal(t, model.StateDeclined, after.State)
				_, err = s.pools.Allocate(l.SubnetID, "other", "", netip.MustParseAddr(l.IP), true)
				require.Error(t, err)
			}
		})
	}
}

func TestDiscoverPreservesBoundLeaseUntilOriginalExpiry(t *testing.T) {
	s := safetyService(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	l := bindSafetyLease(t, s, "02:00:00:aa:00:06")
	now = now.Add(10 * time.Second)
	out, err := s.Handle(ctx, Input{Packet: discover(l.MAC, 3), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, dhcp.MsgOffer, out.Packet.MessageType())
	require.Equal(t, l.IP, out.Packet.YIAddr.String())
	after, err := s.store.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, after)
	// Simulate loss of the REQUEST following this OFFER, then run the janitor.
	now = now.Add(2 * time.Minute)
	require.NoError(t, s.ExpireOnce(ctx))
	out, err = s.Handle(ctx, Input{Packet: discover("02:00:00:aa:00:07", 4), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotEqual(t, l.IP, out.Packet.YIAddr.String())
}

func TestFailedRequestPreservesPreviousAddress(t *testing.T) {
	s := safetyService(t)
	ctx := context.Background()
	l := bindSafetyLease(t, s, "02:00:00:aa:00:08")
	s.store = &failingLeaseStore{Store: s.store, err: errors.New("write failed")}
	newIP := netip.MustParseAddr("192.168.10.180")
	out, err := s.Handle(ctx, Input{Packet: leasePacket(l.MAC, dhcp.MsgRequest, newIP), VLAN: pint(10)})
	require.Error(t, err)
	require.Nil(t, out)
	after, err := s.store.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, after)
	require.True(t, s.pools.Holds(l.SubnetID, "other", netip.MustParseAddr(l.IP)))
}

type gatedLeaseStore struct {
	storage.Store
	loaded chan struct{}
	resume chan struct{}
}

func (s *gatedLeaseStore) ActiveLeases(ctx context.Context, now time.Time) ([]model.Lease, error) {
	ls, err := s.Store.ActiveLeases(ctx, now)
	close(s.loaded)
	<-s.resume
	return ls, err
}

func TestReloadCannotDiscardConcurrentAllocation(t *testing.T) {
	s := safetyService(t)
	ctx := context.Background()
	store := &gatedLeaseStore{Store: s.store, loaded: make(chan struct{}), resume: make(chan struct{})}
	s.store = store
	applied := make(chan error, 1)
	go func() { applied <- s.Apply(ctx, testConfig(t)) }()
	<-store.loaded
	type result struct {
		out *Output
		err error
	}
	allocated := make(chan result, 1)
	go func() {
		out, err := s.Handle(ctx, Input{Packet: discover("02:00:00:aa:00:09", 9), VLAN: pint(10)})
		allocated <- result{out, err}
	}()
	// A request cannot finish while Apply holds a stale lease snapshot.
	select {
	case <-allocated:
		close(store.resume)
		t.Fatal("allocation ran inside an unfinished pool reconciliation")
	case <-time.After(30 * time.Millisecond):
	}
	close(store.resume)
	require.NoError(t, <-applied)
	first := <-allocated
	require.NoError(t, first.err)
	require.NotNil(t, first.out)
	second, err := s.Handle(ctx, Input{Packet: discover("02:00:00:aa:00:0a", 10), VLAN: pint(10)})
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotEqual(t, first.out.Packet.YIAddr, second.Packet.YIAddr)
}
