// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package ddns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
)

type fakeDNS struct {
	records       map[string]storage.DNSRecord
	sets, removes int
	fail          bool
}

func (f *fakeDNS) Set(ctx context.Context, r storage.DNSRecord) error {
	if old, ok := f.records[r.Key()]; ok && old.Token != r.Token {
		return fmt.Errorf("foreign record")
	}
	f.records[r.Key()] = r
	f.sets++
	if f.fail {
		return fmt.Errorf("reply lost after application")
	}
	return nil
}
func (f *fakeDNS) Remove(ctx context.Context, r storage.DNSRecord) error {
	if old, ok := f.records[r.Key()]; ok {
		if old.Token == "" {
			return nil
		}
		if old.Token != r.Token {
			return fmt.Errorf("foreign ownership")
		}
		delete(f.records, r.Key())
	}
	f.removes++
	return nil
}
func fixture(t *testing.T) (*Worker, *config.Config, *fakeDNS, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leases.db")
	st, e := storage.Open(context.Background(), "sqlite", path)
	require.NoError(t, e)
	t.Cleanup(func() { st.Close() })
	require.NoError(t, st.ReplaceCatalog(context.Background(), storage.Catalog{Subnets: []model.Subnet{{ID: "test", Network: "192.0.2.0/24"}}}))
	cfg := &config.Config{DDNS: config.DDNS{Enabled: true, Server: "dc.example.org", Zone: "hosts.example.org", ReverseZones: []string{"2.0.192.in-addr.arpa"}, Principal: "dhcp-dns@EXAMPLE.ORG", Keytab: "/tmp/keytab"}}
	cfg.ApplyDefaults()
	fake := &fakeDNS{records: map[string]storage.DNSRecord{}}
	w, e := New(st, func() *config.Config { return cfg }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, e)
	w.factory = func(context.Context, config.DDNS) (Updater, func(), error) { return fake, func() {}, nil }
	return w, cfg, fake, path
}
func lease(w *Worker, name string) model.Lease {
	return model.Lease{IP: "192.0.2.10", MAC: "02:00:00:00:00:01", SubnetID: "test", Hostname: name, State: model.StateBound, ExpiresAt: w.now().Add(time.Hour)}
}
func TestCommittedLeaseLifecycle(t *testing.T) {
	ctx := context.Background()
	w, _, dns, _ := fixture(t)
	l := lease(w, "printer")
	require.NoError(t, w.store.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Len(t, dns.records, 2)
	state, e := w.state.DNSRecords(ctx)
	require.NoError(t, e)
	require.Len(t, state, 2)
	l.ExpiresAt = l.ExpiresAt.Add(time.Hour)
	require.NoError(t, w.store.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, 4, dns.sets, "renewal refreshes both records")
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, 4, dns.sets, "unchanged records are not rewritten every poll")
	l.Hostname = "renamed"
	require.NoError(t, w.store.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Len(t, dns.records, 2)
	for _, r := range dns.records {
		if r.Type == "A" {
			require.Equal(t, "renamed.hosts.example.org.", r.Name)
		} else {
			require.Equal(t, "renamed.hosts.example.org.", r.Value)
		}
	}
	require.NoError(t, w.store.DeleteLease(ctx, l.IP))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, dns.records)
	state, e = w.state.DNSRecords(ctx)
	require.NoError(t, e)
	require.Empty(t, state)
	for _, state := range []string{model.StateOffered, model.StateDeclined, model.StateReleased, model.StateExpired} {
		l.State = state
		require.NoError(t, w.store.UpsertLease(ctx, l))
		require.NoError(t, w.Reconcile(ctx))
		require.Empty(t, dns.records)
	}
	l.State = model.StateBound
	l.ExpiresAt = w.now().Add(time.Hour)
	require.NoError(t, w.store.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Len(t, dns.records, 2)
	w.now = func() time.Time { return l.ExpiresAt.Add(time.Second) }
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, dns.records, "expiry is handled even before the lease janitor runs")
}
func TestRecoveryAfterDNSAppliedButReplyOrProcessLost(t *testing.T) {
	ctx := context.Background()
	w, cfg, dns, path := fixture(t)
	l := lease(w, "recover")
	require.NoError(t, w.store.UpsertLease(ctx, l))
	dns.fail = true
	require.NoError(t, w.Reconcile(ctx))
	state, e := w.state.DNSRecords(ctx)
	require.NoError(t, e)
	require.Len(t, state, 1, "PTR waits for confirmed A update")
	for _, r := range state {
		require.True(t, r.AppliedAt.IsZero())
	}
	token := state[0].Token
	require.NoError(t, w.store.Close())
	st, e := storage.Open(ctx, "sqlite", path)
	require.NoError(t, e)
	t.Cleanup(func() { st.Close() })
	restarted, e := New(st, func() *config.Config { return cfg }, w.log)
	require.NoError(t, e)
	dns.fail = false
	restarted.factory = w.factory
	require.NoError(t, restarted.Reconcile(ctx))
	state, e = restarted.state.DNSRecords(ctx)
	require.NoError(t, e)
	require.Len(t, state, 2)
	require.Equal(t, token, state[0].Token)
	for _, r := range state {
		require.False(t, r.AppliedAt.IsZero())
	}
	require.NoError(t, restarted.store.DeleteLease(ctx, l.IP))
	require.NoError(t, restarted.Reconcile(ctx))
	require.Empty(t, dns.records)
}
func TestForeignRecordsAndDuplicateNamesAreProtected(t *testing.T) {
	ctx := context.Background()
	w, cfg, dns, _ := fixture(t)
	l := lease(w, "shared")
	require.NoError(t, w.store.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	old := map[string]storage.DNSRecord{}
	for k, v := range dns.records {
		old[k] = v
	}
	other := l
	other.IP = "192.0.2.11"
	other.MAC = "02:00:00:00:00:02"
	require.NoError(t, w.store.UpsertLease(ctx, other))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, old, dns.records)
	require.NoError(t, w.store.DeleteLease(ctx, l.IP))
	require.NoError(t, w.Reconcile(ctx))
	require.Len(t, dns.records, 2)
	for _, r := range dns.records {
		if r.Type == "A" {
			require.Equal(t, other.IP, r.Value)
		}
	}
	cfg.Server.ServerID = "192.0.2.1" // The worker never depends on packet delivery.
	cfg.DDNS.Server = "another.example.org"
	before := dns.removes
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, before, dns.removes, "server change does not clean unconfigured DNS authorities")
	cfg.DDNS.Enabled = false
	require.NoError(t, w.store.DeleteLease(ctx, other.IP))
	require.NoError(t, w.Reconcile(ctx))
	require.NotEmpty(t, dns.records, "disabling pauses cleanup")
}
func TestHostnamePolicy(t *testing.T) {
	_, cfg, _, _ := fixture(t)
	for _, host := range []string{"dc.example.org", "example.org", "wpad", "isatap", "autodiscover", "x.other.org", "x\nsend\nupdate delete example.org A", "x;bad", "-bad", "_ldap"} {
		_, ok := Hostname(host, cfg.DDNS)
		require.False(t, ok, host)
	}
	name, ok := Hostname("DESKTOP-1", cfg.DDNS)
	require.True(t, ok)
	require.Equal(t, "desktop-1.hosts.example.org.", name)
	cfg.DDNS.ProtectedNames = []string{"gateway"}
	_, ok = Hostname("gateway", cfg.DDNS)
	require.False(t, ok)
}
