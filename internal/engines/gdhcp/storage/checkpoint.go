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
	"database/sql"
	"log/slog"
	"time"
)

// Keep checkpoint I/O off the lease writer's single connection. PASSIVE never
// waits for readers or writers. Automatic checkpointing remains a 16384-page
// fallback if maintenance cannot keep up (about 64 MiB with 4 KiB pages).
// User-supplied pragmas keep their own checkpoint policy.
func (s *SQLStore) startCheckpoint(ctx context.Context, dsn string) error {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return err
	}
	s.checkpointDB = db
	maintenance, cancel := context.WithCancel(context.Background())
	s.checkpointCancel = cancel
	s.checkpointDone = make(chan struct{})
	go func() {
		defer close(s.checkpointDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		var reported bool
		for {
			select {
			case <-maintenance.Done():
				return
			case <-ticker.C:
				err := checkpointLeaseWAL(maintenance, db)
				if err != nil && maintenance.Err() == nil {
					if !reported {
						slog.Warn("SQLite background checkpoint failed; automatic checkpoint fallback remains enabled", "err", err)
					}
					reported = true
				} else {
					reported = false
				}
			}
		}
	}()
	return nil
}
