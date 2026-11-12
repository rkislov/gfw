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

package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/stretchr/testify/require"
)

func openTestStore(t *testing.T) Store {
	t.Helper()
	s, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "nested", "leases.db"))
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLeaseLifecycleAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "leases.db")
	s, err := Open(ctx, "sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	require.NoError(t, s.Ping(ctx))
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	vlan := 20
	l := model.Lease{IP: "192.168.20.100", MAC: "aa:bb:cc:dd:ee:ff", ClientID: "client", Hostname: "phone", SubnetID: "voice", VLANID: &vlan, GIAddr: "10.0.0.1", CircuitID: "port1", RemoteID: "switch", LinkSelect: "192.168.20.1", State: "offered", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, s.UpsertLease(ctx, l))
	got, err := s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, got)
	l.State = "bound"
	l.ExpiresAt = now.Add(2 * time.Hour)
	require.NoError(t, s.UpsertLease(ctx, l))
	require.NoError(t, s.Close())
	s, err = Open(ctx, "sqlite", path)
	require.NoError(t, err)
	got, err = s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, got)
	active, err := s.ActiveLeases(ctx, now)
	require.NoError(t, err)
	require.Len(t, active, 1)
	n, err := s.ExpireLeases(ctx, l.ExpiresAt)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	got, err = s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, "expired", got.State)
	require.NoError(t, s.DeleteLease(ctx, l.IP))
	require.ErrorIs(t, s.DeleteLease(ctx, l.IP), ErrNotFound)
	_, err = s.GetLease(ctx, l.IP)
	require.ErrorIs(t, err, ErrNotFound)
	relays, err := s.ListRelays(ctx)
	require.NoError(t, err)
	require.Len(t, relays, 1)
	require.False(t, relays[0].Trusted)
}

func TestLeaseFiltersPaginationAndExpiry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	vlan := 10
	for i, state := range []string{"offered", "bound", "declined", "released", "expired"} {
		l := model.Lease{IP: fmt.Sprintf("192.168.10.%d", 100+i), MAC: fmt.Sprintf("02:00:00:00:00:%02d", i), Hostname: fmt.Sprintf("host%d", i), SubnetID: "office", VLANID: &vlan, GIAddr: "10.0.0.1", CircuitID: "port", State: state, ExpiresAt: now.Add(time.Hour)}
		require.NoError(t, s.UpsertLease(ctx, l))
	}
	for _, f := range []model.LeaseFilter{{}, {Limit: 1001}, {VLAN: &vlan, SubnetID: "office", GIAddr: "10.0.0.1", State: "bound", Query: "host1"}, {Query: "port"}, {Query: "192.168"}, {Query: "02:00"}} {
		rows, total, err := s.ListLeases(ctx, f)
		require.NoError(t, err)
		if f.State != "" {
			require.Equal(t, 1, total)
		} else {
			require.Equal(t, 5, total)
		}
		require.Len(t, rows, total)
	}
	rows, total, err := s.ListLeases(ctx, model.LeaseFilter{Limit: 2, Offset: 1})
	require.NoError(t, err)
	require.Equal(t, 5, total)
	require.Len(t, rows, 2)
	require.Equal(t, "192.168.10.101", rows[0].IP)
	active, err := s.ActiveLeases(ctx, now)
	require.NoError(t, err)
	require.Len(t, active, 3)
	n, err := s.ExpireLeases(ctx, now.Add(2*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	active, err = s.ActiveLeases(ctx, now)
	require.NoError(t, err)
	require.Empty(t, active)
}

func TestCatalogReplacementRollbackAndReservations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	vlan := 10
	cat := Catalog{
		VLANs:        []model.VLAN{{ID: 10, Name: "office", Interface: "eth0.10", Priority: 5, Source: "local", SubnetID: "office"}},
		Subnets:      []model.Subnet{{ID: "office", Network: "192.168.10.0/24", RangeStart: "192.168.10.100", RangeEnd: "192.168.10.200", Gateway: "192.168.10.1", VLANID: &vlan, Domain: "lan", DNS: []string{"1.1.1.1"}, Options: map[string]string{"66": "tftp"}, LeaseSec: 3600}},
		Relays:       []model.Relay{{GIAddr: "10.0.0.1", RemoteID: "relay", Vendor: "cisco", Trusted: true, ParserName: "cisco", VLANID: &vlan, SubnetID: "office", CreatedAt: time.Now().UTC()}},
		Reservations: []model.Reservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.10.20", SubnetID: "office", Hostname: "printer"}},
	}
	require.NoError(t, s.ReplaceCatalog(ctx, cat))
	vs, err := s.ListVLANs(ctx)
	require.NoError(t, err)
	require.Equal(t, cat.VLANs, vs)
	subs, err := s.ListSubnets(ctx)
	require.NoError(t, err)
	require.Equal(t, cat.Subnets, subs)
	rs, err := s.ListRelays(ctx)
	require.NoError(t, err)
	require.Equal(t, cat.Relays, rs)
	reservations, err := s.ListReservations(ctx)
	require.NoError(t, err)
	require.Len(t, reservations, 1)
	added, err := s.CreateReservation(ctx, model.Reservation{ClientID: "cid", IP: "192.168.10.21", SubnetID: "office"})
	require.NoError(t, err)
	require.Positive(t, added.ID)
	reservations, err = s.ListReservations(ctx)
	require.NoError(t, err)
	require.Len(t, reservations, 2)
	require.Equal(t, added, reservations[1])
	require.NoError(t, s.DeleteReservation(ctx, added.ID))
	require.ErrorIs(t, s.DeleteReservation(ctx, added.ID), ErrNotFound)
	bad := cat
	bad.VLANs = append(append([]model.VLAN{}, cat.VLANs...), cat.VLANs[0])
	require.Error(t, s.ReplaceCatalog(ctx, bad))
	vs, err = s.ListVLANs(ctx)
	require.NoError(t, err)
	require.Equal(t, cat.VLANs, vs, "failed transaction must retain catalog")
	require.NoError(t, s.UpsertLease(ctx, model.Lease{IP: "192.168.10.100", MAC: "a", State: "bound", ExpiresAt: time.Now().Add(time.Hour)}))
	require.NoError(t, s.ReplaceCatalog(ctx, Catalog{}))
	vs, err = s.ListVLANs(ctx)
	require.NoError(t, err)
	require.Empty(t, vs)
	_, err = s.GetLease(ctx, "192.168.10.100")
	require.NoError(t, err, "catalog replacement must preserve leases")
}

func TestClosedStoreAndInvalidOpen(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	require.NoError(t, s.Close())
	require.Error(t, s.Ping(ctx))
	require.Error(t, s.UpsertLease(ctx, model.Lease{}))
	_, err := s.GetLease(ctx, "x")
	require.Error(t, err)
	_, _, err = s.ListLeases(ctx, model.LeaseFilter{})
	require.Error(t, err)
	require.Error(t, s.DeleteLease(ctx, "x"))
	_, err = s.ActiveLeases(ctx, time.Now())
	require.Error(t, err)
	_, err = s.ExpireLeases(ctx, time.Now())
	require.Error(t, err)
	require.Error(t, s.ReplaceCatalog(ctx, Catalog{}))
	_, err = s.ListVLANs(ctx)
	require.Error(t, err)
	_, err = s.ListSubnets(ctx)
	require.Error(t, err)
	_, err = s.ListRelays(ctx)
	require.Error(t, err)
	_, err = s.ListReservations(ctx)
	require.Error(t, err)
	_, err = s.CreateReservation(ctx, model.Reservation{})
	require.Error(t, err)
	require.Error(t, s.DeleteReservation(ctx, 1))
	_, err = Open(ctx, "unknown", "")
	require.Error(t, err)
	_, err = Open(ctx, "sqlite", t.TempDir())
	require.Error(t, err)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = Open(canceled, "sqlite", ":memory:")
	require.Error(t, err)
}

func TestSQLiteURIsAndPostgresPlaceholders(t *testing.T) {
	for _, dsn := range []string{":memory:", "file::memory:", "file:test?mode=memory", "file:test?mode=memory&_pragma=foreign_keys(ON)"} {
		s, err := Open(context.Background(), "sqlite", dsn)
		require.NoError(t, err)
		require.NoError(t, s.Close())
	}
	s := SQLStore{postgres: true}
	require.Equal(t, "SELECT $1, $2", s.q("SELECT ?, ?"))
	require.True(t, parseTime("").IsZero())
	require.True(t, parseTime("invalid").IsZero())
}

func TestRenewalPreservesCreationAndUpdatesRelayMetadata(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	vlan := 10
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := model.Lease{IP: "192.168.10.100", MAC: "02:00:00:00:10:01", ClientID: "cid", SubnetID: "office", VLANID: &vlan, State: "bound", CreatedAt: created, ExpiresAt: created.Add(time.Hour)}
	require.NoError(t, s.UpsertLease(ctx, l))
	l.CreatedAt = created.Add(30 * time.Minute)
	l.GIAddr = "10.0.0.1"
	l.CircuitID = "port1"
	l.RemoteID = "relay"
	l.LinkSelect = "192.168.10.1"
	l.Hostname = "renamed"
	l.ExpiresAt = created.Add(2 * time.Hour)
	require.NoError(t, s.UpsertLease(ctx, l))
	got, err := s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	l.CreatedAt = created
	require.Equal(t, l, got)
	relays, err := s.ListRelays(ctx)
	require.NoError(t, err)
	require.Len(t, relays, 1)
	// A relay's automatic catalog row must also be recreated after catalog replacement.
	require.NoError(t, s.ReplaceCatalog(ctx, Catalog{}))
	require.NoError(t, s.UpsertLease(ctx, l))
	relays, err = s.ListRelays(ctx)
	require.NoError(t, err)
	require.Len(t, relays, 1)
	l.GIAddr = ""
	l.RemoteID = ""
	l.CircuitID = ""
	l.LinkSelect = ""
	l.ExpiresAt = created.Add(3 * time.Hour)
	require.NoError(t, s.UpsertLease(ctx, l))
	got, err = s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, got)
	// A different binding identity must take the full UPSERT path, not a partial renewal.
	l.MAC = "02:00:00:00:10:02"
	l.ClientID = "other"
	l.SubnetID = "other-subnet"
	otherVLAN := 20
	l.VLANID = &otherVLAN
	require.NoError(t, s.UpsertLease(ctx, l))
	got, err = s.GetLease(ctx, l.IP)
	require.NoError(t, err)
	require.Equal(t, l, got)
}

func TestLeaseTransactionReadYourWritesAndRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	batch := s.(interface {
		WithLeaseTransaction(context.Context, func(context.Context) error) error
	})
	l := model.Lease{IP: "192.0.2.10", MAC: "client", SubnetID: "lan", State: "bound", ExpiresAt: time.Now().Add(time.Hour)}
	stop := errors.New("reject transaction")
	err := batch.WithLeaseTransaction(ctx, func(txCtx context.Context) error {
		require.NoError(t, s.UpsertLease(txCtx, l))
		got, err := s.GetLease(txCtx, l.IP)
		require.NoError(t, err)
		require.Equal(t, l.MAC, got.MAC)
		active, err := s.ActiveLeases(txCtx, time.Now())
		require.NoError(t, err)
		require.Len(t, active, 1)
		return stop
	})
	require.ErrorIs(t, err, stop)
	_, err = s.GetLease(ctx, l.IP)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, batch.WithLeaseTransaction(ctx, func(txCtx context.Context) error { return s.UpsertLease(txCtx, l) }))
	_, err = s.GetLease(ctx, l.IP)
	require.NoError(t, err)
}

func TestLeaseBatchRollsBackFirstWriteWhenSecondWriteFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t).(*SQLStore)
	_, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_second BEFORE INSERT ON leases WHEN NEW.ip = '192.0.2.11' BEGIN SELECT RAISE(ABORT, 'disk write rejected'); END`)
	require.NoError(t, err)
	err = s.WithLeaseTransaction(ctx, func(txCtx context.Context) error {
		l := model.Lease{IP: "192.0.2.10", MAC: "first", State: "bound", ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.UpsertLease(txCtx, l); err != nil {
			return err
		}
		l.IP = "192.0.2.11"
		l.MAC = "second"
		return s.UpsertLease(txCtx, l)
	})
	require.ErrorContains(t, err, "disk write rejected")
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		_, err = s.GetLease(ctx, ip)
		require.ErrorIs(t, err, ErrNotFound)
	}
}

func TestNestedLeaseBatchIsRejected(t *testing.T) {
	s := openTestStore(t).(*SQLStore)
	err := s.WithLeaseTransaction(context.Background(), func(txCtx context.Context) error {
		return s.WithLeaseTransaction(txCtx, func(context.Context) error { t.Fatal("nested callback ran"); return nil })
	})
	require.ErrorContains(t, err, "nested lease transaction")
}
