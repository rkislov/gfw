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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/stretchr/testify/require"
)

func TestCheckpointLifecycleAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "leases.db")
	store, err := Open(ctx, "sqlite", path)
	require.NoError(t, err)
	s := store.(*SQLStore)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.NotNil(t, s.checkpointDB)
	var threshold int
	require.NoError(t, s.db.QueryRow("PRAGMA wal_autocheckpoint").Scan(&threshold))
	require.Equal(t, 16384, threshold)
	var cacheKB int
	require.NoError(t, s.db.QueryRow("PRAGMA cache_size").Scan(&cacheKB))
	require.Equal(t, -32768, cacheKB)
	lease := model.Lease{IP: "192.0.2.10", MAC: "02:00:00:00:00:10", State: model.StateBound, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	require.NoError(t, s.UpsertLease(ctx, lease))
	// Background checkpoints must not require another lease write to make progress.
	require.Eventually(t, func() bool {
		// A checkpoint must copy this newly inserted value from WAL into
		// the main database without another write or closing the store.
		data, err := os.ReadFile(path)
		return err == nil && bytes.Contains(data, []byte(lease.MAC))
	}, 3*time.Second, 20*time.Millisecond)
	require.NoError(t, s.Close())
	select {
	case <-s.checkpointDone:
	default:
		t.Fatal("checkpoint worker survived Close")
	}
	require.NoError(t, s.Close())
	reopened, err := Open(ctx, "sqlite", path)
	require.NoError(t, err)
	defer reopened.Close()
	got, err := reopened.GetLease(ctx, lease.IP)
	require.NoError(t, err)
	require.Equal(t, lease.MAC, got.MAC)
}

func TestCheckpointHonorsCustomPragmasAndMemory(t *testing.T) {
	for _, dsn := range []string{":memory:", "file:" + filepath.Join(t.TempDir(), "custom.db") + "?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(25)", "file:" + filepath.Join(t.TempDir(), "custom-default.db") + "?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(16384)"} {
		s, err := Open(context.Background(), "sqlite", dsn)
		require.NoError(t, err)
		require.Nil(t, s.(*SQLStore).checkpointDB)
		require.NoError(t, s.Close())
	}
}

// The pragma is connection-local. Renewing a database/sql connection must not
// silently restore the small SQLite default cache under sustained traffic.
func TestLeaseCacheSurvivesConnectionRotation(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "rotate.db"))
	require.NoError(t, err)
	defer store.Close()
	s := store.(*SQLStore)
	s.db.SetConnMaxLifetime(time.Nanosecond)
	for range 3 {
		var size int
		require.NoError(t, s.db.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&size))
		require.Equal(t, -32768, size)
	}
}

func TestCustomLeaseCacheIsPreserved(t *testing.T) {
	store, err := Open(context.Background(), "sqlite", "file:"+filepath.Join(t.TempDir(), "custom-cache.db")+"?_pragma=journal_mode(WAL)&_pragma=cache_size(-1024)")
	require.NoError(t, err)
	defer store.Close()
	s := store.(*SQLStore)
	var size int
	require.NoError(t, s.db.QueryRow("PRAGMA cache_size").Scan(&size))
	require.Equal(t, -1024, size)
	require.Nil(t, s.checkpointDB)
}
