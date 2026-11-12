// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIPv6ConcurrentOwnershipAndExpiry(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { checkIPv6Ownership(t, "sqlite", filepath.Join(t.TempDir(), "leases.db")) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("GODHCP_TEST_IPV6_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("set a disposable PostgreSQL DSN")
		}
		checkIPv6Ownership(t, "postgres", dsn)
	})
}

func checkIPv6Ownership(t *testing.T, driver, dsn string) {
	ctx := context.Background()
	ports := make([]IPv6Store, 2)
	for i := range ports {
		s, err := Open(ctx, driver, dsn)
		require.NoError(t, err)
		t.Cleanup(func() { s.Close() })
		ports[i] = s.(IPv6Store)
		_, err = ports[i].InitIPv6(ctx, nil)
		require.NoError(t, err)
	}
	r := IPv6Request{Action: Bind6, Prefix: "fd00:feed::/64", Start: netip.MustParseAddr("fd00:feed::10"), End: netip.MustParseAddr("fd00:feed::10"), Now: time.Now(), Lifetime: time.Minute}
	var wg sync.WaitGroup
	errs := make([]error, len(ports))
	for i, db := range ports {
		wg.Go(func() {
			request := r
			request.Client = []string{"one", "two"}[i]
			_, errs[i] = db.ApplyIPv6(ctx, request)
		})
	}
	wg.Wait()
	require.ElementsMatch(t, []error{nil, ErrNoAddress6}, errs)
	r.Now = r.Now.Add(time.Minute)
	r.Client = "three"
	ip, err := ports[0].ApplyIPv6(ctx, r)
	require.NoError(t, err)
	require.Equal(t, r.Start, ip)
	r.Action = Decline6
	r.Hints = []netip.Addr{ip}
	r.Lifetime = time.Hour
	_, err = ports[1].ApplyIPv6(ctx, r)
	require.NoError(t, err)
	r.Action = Bind6
	r.Client = "four"
	r.Now = r.Now.Add(time.Minute)
	_, err = ports[1].ApplyIPv6(ctx, r)
	require.ErrorIs(t, err, ErrNoAddress6)
	r.Now = r.Now.Add(time.Hour)
	_, err = ports[0].ApplyIPv6(ctx, r)
	require.NoError(t, err)
}
