// Copyright 2026 Кислов Роман Сергеевич
// Licensed under the Apache License, Version 2.0.

package pool

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMovingClientDoesNotFreePreviousLease(t *testing.T) {
	m := New()
	spec := Spec{ID: "lan", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Start: netip.MustParseAddr("192.0.2.10"), End: netip.MustParseAddr("192.0.2.20")}
	m.Reconcile([]Spec{spec}, nil)
	old, err := m.Allocate("lan", "client", "", spec.Start, true)
	require.NoError(t, err)
	_, err = m.Allocate("lan", "client", "", spec.Start.Next(), true)
	require.NoError(t, err)
	_, err = m.Allocate("lan", "other", "", old, true)
	require.ErrorIs(t, err, ErrConflict)
	m.Release(old.String(), "client")
	_, err = m.Allocate("lan", "other", "", old, true)
	require.NoError(t, err)
}

// Retain an operation-scale benchmark for the 100k-lease renewal path.
func BenchmarkRenewAt100KLeases(b *testing.B) {
	m := New()
	start := netip.MustParseAddr("198.18.0.10")
	spec := Spec{ID: "load", Prefix: netip.MustParsePrefix("198.18.0.0/15"), Start: start, End: netip.MustParseAddr("198.19.255.254")}
	active := make([]Binding, 100000)
	ip := start
	for i := range active {
		active[i] = Binding{IP: ip.String(), MAC: fmt.Sprintf("client-%d", i)}
		ip = ip.Next()
	}
	m.Reconcile([]Spec{spec}, active)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Allocate("load", "client-0", "", start, true); err != nil {
			b.Fatal(err)
		}
	}
}

func TestHoldingHistoricalLeasePreservesCurrentMACIndex(t *testing.T) {
	m := New()
	spec := Spec{ID: "lan", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Start: netip.MustParseAddr("192.0.2.10"), End: netip.MustParseAddr("192.0.2.20")}
	old, current := spec.Start, spec.Start.Next()
	m.Reconcile([]Spec{spec}, []Binding{{IP: old.String(), MAC: "client"}, {IP: current.String(), MAC: "client"}})
	m.Hold(old.String())
	got, err := m.Allocate("lan", "client", "", netip.Addr{}, false)
	require.NoError(t, err)
	require.Equal(t, current, got)
	require.True(t, m.Holds("lan", "other", old))
}

func TestReservationReassignmentRemovesPreviousMACIndex(t *testing.T) {
	m := New()
	ip := netip.MustParseAddr("192.0.2.10")
	spec := Spec{ID: "lan", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Start: ip, End: ip.Next(), Reservations: []Reservation{{IP: ip, ClientID: "reserved-client"}}}
	m.Reconcile([]Spec{spec}, []Binding{{IP: ip.String(), MAC: "old", ClientID: "reserved-client"}})
	m.Bind("lan", ip.String(), "new", "reserved-client")
	require.True(t, m.Holds("lan", "old", ip))
	require.False(t, m.Holds("lan", "new", ip))
	require.NotContains(t, m.pools["lan"].byMAC, "old")
	m.Release(ip.String(), "new")
	require.NotContains(t, m.pools["lan"].byMAC, "new")
}
