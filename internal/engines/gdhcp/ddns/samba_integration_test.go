//go:build integration

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package ddns

import (
	"context"
	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSambaDNSLifecycle(t *testing.T) {
	if os.Getenv("GODHCP_DDNS_GSS_TEST") != "1" {
		t.Skip("run scripts/test-ddns-samba.sh in an isolated disposable domain")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "leases.db")
	st, e := storage.Open(ctx, "sqlite", path)
	require.NoError(t, e)
	require.NoError(t, st.ReplaceCatalog(ctx, storage.Catalog{Subnets: []model.Subnet{{ID: "test", Network: "192.0.2.0/24"}}}))
	cfg := &config.Config{DDNS: config.DDNS{Enabled: true, Server: "dc.dhcp.test", Zone: "hosts.dhcp.test", ReverseZones: []string{"2.0.192.in-addr.arpa"}, Principal: "dhcp-dns@DHCP.TEST", Keytab: "/tmp/dhcp-dns.keytab"}}
	cfg.ApplyDefaults()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w, e := New(st, func() *config.Config { return cfg }, log)
	require.NoError(t, e)
	query := func(name, typ string) string {
		out, e := exec.Command("dig", "@127.0.0.1", name, typ, "+short").CombinedOutput()
		require.NoError(t, e, string(out))
		return strings.TrimSpace(string(out))
	}
	l := model.Lease{IP: "192.0.2.10", MAC: "02:00:00:00:00:10", Hostname: "gss-client", SubnetID: "test", State: model.StateBound, ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, l.IP, query("gss-client.hosts.dhcp.test", "A"))
	require.Equal(t, "gss-client.hosts.dhcp.test.", query("10.2.0.192.in-addr.arpa", "PTR"))
	require.NotEmpty(t, query("_godhcp-owner.gss-client.hosts.dhcp.test", "TXT"))
	l.ExpiresAt = l.ExpiresAt.Add(time.Hour)
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, l.IP, query("gss-client.hosts.dhcp.test", "A"))
	// Crash/restart preserves the identity and authoritative ownership markers.
	require.NoError(t, st.Close())
	st, e = storage.Open(ctx, "sqlite", path)
	require.NoError(t, e)
	defer st.Close()
	w, e = New(st, func() *config.Config { return cfg }, log)
	require.NoError(t, e)
	l.Hostname = "renamed"
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, query("gss-client.hosts.dhcp.test", "A"))
	require.Equal(t, l.IP, query("renamed.hosts.dhcp.test", "A"))
	require.Equal(t, "renamed.hosts.dhcp.test.", query("10.2.0.192.in-addr.arpa", "PTR"))
	// Reusing an IP for a different client removes the previous client's names.
	l.MAC = "02:00:00:00:00:11"
	l.Hostname = "replacement"
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, query("renamed.hosts.dhcp.test", "A"))
	require.Equal(t, l.IP, query("replacement.hosts.dhcp.test", "A"))
	l.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, query("replacement.hosts.dhcp.test", "A"))
	require.Empty(t, query("10.2.0.192.in-addr.arpa", "PTR"))
	require.Empty(t, query("_godhcp-owner.replacement.hosts.dhcp.test", "TXT"))
	// Neither claiming nor deleting a DHCP intent may overwrite an administrator's A RR.
	l.Hostname = "foreign"
	l.ExpiresAt = time.Now().Add(time.Hour)
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, "192.0.2.250", query("foreign.hosts.dhcp.test", "A"))
	require.Empty(t, query("10.2.0.192.in-addr.arpa", "PTR"))
	require.NoError(t, st.DeleteLease(ctx, l.IP))
	require.NoError(t, w.Reconcile(ctx))
	require.Equal(t, "192.0.2.250", query("foreign.hosts.dhcp.test", "A"))
	require.Empty(t, query("10.2.0.192.in-addr.arpa", "PTR"))
	pending, e := w.state.DNSRecords(ctx)
	require.NoError(t, e)
	require.Empty(t, pending)
	// PTR-only mode leaves the forward record under the client's control.
	no := false
	cfg.DDNS.UpdateA = &no
	l.Hostname = "ptr-only"
	require.NoError(t, st.UpsertLease(ctx, l))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, query("ptr-only.hosts.dhcp.test", "A"))
	require.Equal(t, "ptr-only.hosts.dhcp.test.", query("10.2.0.192.in-addr.arpa", "PTR"))
	require.NoError(t, st.DeleteLease(ctx, l.IP))
	require.NoError(t, w.Reconcile(ctx))
	require.Empty(t, query("10.2.0.192.in-addr.arpa", "PTR"))
}
