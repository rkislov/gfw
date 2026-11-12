package store

import (
	"context"
	"time"

	"github.com/rkislov/gfw/internal/feed"
)

type FeedStatus struct {
	AttemptAt string       `json:"attempt_at,omitempty"`
	SuccessAt string       `json:"success_at,omitempty"`
	Error     string       `json:"error,omitempty"`
	Entries   []feed.Entry `json:"entries"`
}

func (s *Store) initFeed() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS feed_status(
 id INTEGER PRIMARY KEY CHECK(id=1), attempt_at TEXT NOT NULL, success_at TEXT NOT NULL, error TEXT NOT NULL);
INSERT OR IGNORE INTO feed_status VALUES(1,'','','');
CREATE TABLE IF NOT EXISTS feed_snapshot(
 name TEXT PRIMARY KEY, count INTEGER NOT NULL, sha256 TEXT NOT NULL, source TEXT NOT NULL,
 raw BLOB NOT NULL, normalized BLOB);`)
	return err
}

func (s *Store) FeedStatus(ctx context.Context) (FeedStatus, error) {
	out := FeedStatus{Entries: []feed.Entry{}}
	err := s.db.QueryRowContext(ctx, "SELECT attempt_at,success_at,error FROM feed_status WHERE id=1").
		Scan(&out.AttemptAt, &out.SuccessAt, &out.Error)
	if err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT name,count,sha256,source FROM feed_snapshot ORDER BY name")
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var e feed.Entry
		if err = rows.Scan(&e.Name, &e.Count, &e.SHA256, &e.Source); err != nil {
			return out, err
		}
		out.Entries = append(out.Entries, e)
	}
	return out, rows.Err()
}

func (s *Store) RecordFeedAttempt(ctx context.Context, revision int64, actor, message string, entries []feed.Entry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	action := "feed.refresh.failed"
	if message == "" {
		action = "feed.refresh"
		for _, entry := range entries {
			_, err := tx.ExecContext(ctx, `INSERT INTO feed_snapshot VALUES(?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET count=excluded.count, sha256=excluded.sha256,
source=excluded.source,raw=excluded.raw,normalized=excluded.normalized
WHERE sha256<>excluded.sha256 OR source<>excluded.source`,
				entry.Name, entry.Count, entry.SHA256, entry.Source, entry.Raw, entry.Normalized)
			if err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE feed_status SET attempt_at=?,success_at=?,error='' WHERE id=1", now, now)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE feed_status SET attempt_at=?,error=? WHERE id=1", now, message)
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, actor, action, revision)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReadFeedFile(ctx context.Context, name string, normalized bool) ([]byte, error) {
	q := "SELECT raw FROM feed_snapshot WHERE name=?"
	if normalized {
		q = "SELECT normalized FROM feed_snapshot WHERE name=? AND normalized IS NOT NULL"
	}
	var body []byte
	err := s.db.QueryRowContext(ctx, q, name).Scan(&body)
	return body, err
}

// ReadFeedProjection selects the exact version the administrator reviewed.
func (s *Store) ReadFeedProjection(ctx context.Context, name, sha string) ([]byte, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, "SELECT normalized FROM feed_snapshot WHERE name=? AND sha256=? AND normalized IS NOT NULL", name, sha).Scan(&body)
	return body, err
}

func (s *Store) ReadIOCFile(ctx context.Context) (sha, at string, body []byte, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT sha256, success_at, raw FROM feed_snapshot JOIN feed_status ON feed_status.id=1 WHERE name='iocs.json'").
		Scan(&sha, &at, &body)
	return
}
