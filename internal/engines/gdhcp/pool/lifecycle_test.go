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

package pool

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"net/netip"
	"sync"
	"testing"
)

func testSpec() Spec {
	return Spec{ID: "lan", Prefix: netip.MustParsePrefix("192.0.2.0/29"), Start: netip.MustParseAddr("192.0.2.0"), End: netip.MustParseAddr("192.0.2.7"), Gateway: netip.MustParseAddr("192.0.2.1"), VLAN: 10}
}

func TestAllocationExclusionsExhaustionAndRelease(t *testing.T) {
	m := New()
	spec := testSpec()
	m.Reconcile([]Spec{spec}, nil)
	var allocated []netip.Addr
	for i := 0; i < 5; i++ {
		addr, err := m.Allocate("lan", fmt.Sprint(i), "", netip.Addr{}, false)
		require.NoError(t, err)
		allocated = append(allocated, addr)
		require.Equal(t, fmt.Sprintf("192.0.2.%d", i+2), addr.String())
	}
	_, err := m.Allocate("lan", "extra", "", netip.Addr{}, false)
	require.ErrorIs(t, err, ErrExhausted)
	_, err = m.Allocate("missing", "extra", "", netip.Addr{}, false)
	require.ErrorIs(t, err, ErrUnknownSubnet)
	same, err := m.Allocate("lan", "0", "", netip.Addr{}, false)
	require.NoError(t, err)
	require.Equal(t, allocated[0], same)
	require.True(t, m.Holds("lan", "other", same))
	require.False(t, m.Holds("lan", "0", same))
	require.False(t, m.Holds("missing", "0", same))
	m.Release(same.String(), "wrong")
	require.True(t, m.Holds("lan", "other", same))
	m.Release(same.String(), "0")
	addr, err := m.Allocate("lan", "new", "cid", same, true)
	require.NoError(t, err)
	require.Equal(t, same, addr)
	for _, ip := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.7", "192.0.3.10"} {
		_, err = m.Allocate("lan", "new", "", netip.MustParseAddr(ip), true)
		require.ErrorIs(t, err, ErrNotInPool)
	}
	stats := m.Stats()
	require.Len(t, stats, 1)
	require.Equal(t, 5, stats[0].Size)
	require.Equal(t, 5, stats[0].Used)
	require.Zero(t, stats[0].Free)
	require.Equal(t, "pools=1", m.String())
	id, ok := m.SubnetOf(same)
	require.True(t, ok)
	require.Equal(t, "lan", id)
	_, ok = m.SubnetOf(netip.MustParseAddr("203.0.113.1"))
	require.False(t, ok)
	m.Release("invalid", "")
	m.Release("203.0.113.1", "")
	m.Hold("invalid")
}

func TestReservationsHoldAndRestore(t *testing.T) {
	m := New()
	spec := testSpec()
	rmac := netip.MustParseAddr("192.0.2.5")
	rcid := netip.MustParseAddr("192.0.2.6")
	spec.Reservations = []Reservation{{IP: rmac, MAC: "printer"}, {IP: rcid, ClientID: "phone"}}
	m.Reconcile([]Spec{spec}, []Binding{{IP: "192.0.2.2", MAC: "restored", ClientID: "old"}, {IP: "invalid"}, {IP: "203.0.113.1"}})
	for _, tc := range []struct {
		mac, cid string
		want     netip.Addr
	}{{"printer", "", rmac}, {"different", "phone", rcid}, {"restored", "old", netip.MustParseAddr("192.0.2.2")}} {
		addr, err := m.Allocate("lan", tc.mac, tc.cid, netip.Addr{}, false)
		require.NoError(t, err)
		require.Equal(t, tc.want, addr)
	}
	for _, tc := range []struct{ mac, cid string }{{"printer", ""}, {"other", "phone"}} {
		_, err := m.Allocate("lan", tc.mac, tc.cid, spec.Start.Next().Next(), true)
		require.ErrorIs(t, err, ErrConflict)
	}
	_, err := m.Allocate("lan", "intruder", "", rmac, true)
	require.ErrorIs(t, err, ErrConflict)
	m.Release(rmac.String(), "printer")
	m.Hold(rmac.String())
	require.True(t, m.Holds("lan", "other", rmac))
	m.Hold("192.0.2.2")
	replacement, err := m.Allocate("lan", "restored", "old", netip.Addr{}, false)
	require.NoError(t, err)
	require.NotEqual(t, "192.0.2.2", replacement.String())
	m.Release("192.0.2.2", "")
	m.Bind("lan", "192.0.2.2", "new", "new-cid")
	require.True(t, m.Holds("lan", "restored", netip.MustParseAddr("192.0.2.2")))
	m.Bind("missing", "192.0.2.2", "x", "")
	m.Bind("lan", "bad", "x", "")
	require.True(t, m.Contains("lan", rmac))
	require.False(t, m.Contains("missing", rmac))
	require.False(t, m.Contains("lan", netip.MustParseAddr("203.0.113.1")))
	spec.Start = netip.Addr{}
	spec.End = netip.Addr{}
	m.Reconcile([]Spec{spec}, nil)
	require.True(t, m.Contains("lan", netip.MustParseAddr("192.0.2.3")))
	_, err = m.Allocate("lan", "unknown", "", netip.Addr{}, false)
	require.ErrorIs(t, err, ErrExhausted)
}

func TestConcurrentAllocationDoesNotDuplicate(t *testing.T) {
	m := New()
	spec := Spec{ID: "lan", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Start: netip.MustParseAddr("192.0.2.10"), End: netip.MustParseAddr("192.0.2.109")}
	m.Reconcile([]Spec{spec}, nil)
	var wg sync.WaitGroup
	ips := make(chan netip.Addr, 100)
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip, err := m.Allocate("lan", fmt.Sprint(i), "", netip.Addr{}, false)
			ips <- ip
			errs <- err
		}(i)
	}
	wg.Wait()
	close(ips)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	seen := map[netip.Addr]bool{}
	for ip := range ips {
		require.False(t, seen[ip], "duplicate %s", ip)
		seen[ip] = true
	}
	require.Len(t, seen, 100)
}
