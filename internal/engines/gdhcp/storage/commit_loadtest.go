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

//go:build loadtest

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"runtime/trace"
	"time"
)

var commitLog = func() *os.File {
	path := os.Getenv("GODHCP_COMMIT_LOG")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	return f
}()

func commitLeaseTx(tx *sql.Tx) error {
	if commitLog == nil {
		return tx.Commit()
	}
	start := time.Now()
	region := trace.StartRegion(context.Background(), "sqlite.commit")
	err := tx.Commit()
	region.End()
	elapsed := time.Since(start)
	captureSlowStorage(elapsed)
	if elapsed >= 5*time.Millisecond {
		json.NewEncoder(commitLog).Encode(map[string]any{"kind": "commit", "start_unix_ns": start.UnixNano(), "duration_ns": elapsed.Nanoseconds(), "error": err != nil})
	}
	return err
}

func checkpointLeaseWAL(ctx context.Context, db *sql.DB) error {
	start := time.Now()
	region := trace.StartRegion(ctx, "sqlite.checkpoint")
	var busy, frames, copied int
	err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied)
	region.End()
	captureSlowStorage(time.Since(start))
	if commitLog != nil {
		json.NewEncoder(commitLog).Encode(map[string]any{"kind": "checkpoint", "start_unix_ns": start.UnixNano(), "duration_ns": time.Since(start).Nanoseconds(), "busy": busy, "frames": frames, "copied": copied, "error": err != nil})
	}
	return err
}
