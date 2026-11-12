// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDDNSFQDNNegotiationAndRenewalWithoutHostname(t *testing.T) {
	s := safetyService(t)
	ctx := context.Background()
	cfg := s.Config()
	cfg.DDNS = config.DDNS{Enabled: true, Server: "dc.example.org", Zone: "example.org", ReverseZones: []string{"10.168.192.in-addr.arpa"}, Principal: "dhcp@EXAMPLE.ORG", Keytab: "/etc/godhcp/dhcp.keytab"}
	require.NoError(t, s.Apply(ctx, cfg))
	mac := "02:00:00:00:00:19"
	d := discover(mac, 1)
	d.Set(dhcp.OptHostname, []byte("ignored"))
	d.Append(dhcp.FQDNOption(dhcp.FQDNEncoded, "fqdn-client"))
	offer, e := s.Handle(ctx, Input{Packet: d, VLAN: pint(10)})
	require.NoError(t, e)
	require.NotNil(t, offer)
	f, ok := offer.Packet.ClientFQDN()
	require.True(t, ok)
	require.Equal(t, "fqdn-client.example.org.", f.Name)
	require.Equal(t, dhcp.FQDNEncoded|dhcp.FQDNServer|dhcp.FQDNOverride, f.Flags)
	ip := offer.Packet.YIAddr
	r := leasePacket(mac, dhcp.MsgRequest, ip)
	r.Append(dhcp.FQDNOption(dhcp.FQDNEncoded, "fqdn-client"))
	ack, e := s.Handle(ctx, Input{Packet: r, VLAN: pint(10)})
	require.NoError(t, e)
	require.NotNil(t, ack)
	bound, e := s.Store().GetLease(ctx, ip.String())
	require.NoError(t, e)
	require.Equal(t, "fqdn-client", bound.Hostname)
	// Many clients omit Host Name during unicast renewal. Do not erase DNS identity.
	renew := leasePacket(mac, dhcp.MsgRequest, ip)
	ack, e = s.Handle(ctx, Input{Packet: renew, VLAN: pint(10)})
	require.NoError(t, e)
	require.NotNil(t, ack)
	bound, e = s.Store().GetLease(ctx, ip.String())
	require.NoError(t, e)
	require.Equal(t, "fqdn-client", bound.Hostname)
	r.Set(dhcp.OptClientFQDN, dhcp.FQDNOption(dhcp.FQDNEncoded|dhcp.FQDNNoUpdate, "fqdn-client").Data)
	ack, e = s.Handle(ctx, Input{Packet: r, VLAN: pint(10)})
	require.NoError(t, e)
	f, ok = ack.Packet.ClientFQDN()
	require.True(t, ok)
	require.Equal(t, dhcp.FQDNEncoded|dhcp.FQDNNoUpdate, f.Flags)
	bound, e = s.Store().GetLease(ctx, ip.String())
	require.NoError(t, e)
	require.Empty(t, bound.Hostname, "N flag withdraws previous server-owned DNS name")
}
