package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/traffic"
)

const trafficQueueLimit = 50_000
const SIEMTrafficBatch = 250

type SIEMTrafficStats struct {
	Queued   int64  `json:"queued"`
	Evicted  int64  `json:"evicted"`
	LastSent string `json:"last_sent,omitempty"`
}

func (s *Store) initSIEMTraffic() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS siem_traffic(
		id INTEGER PRIMARY KEY CHECK(id=1), filter TEXT NOT NULL, evicted INTEGER NOT NULL, last_sent TEXT NOT NULL);
		INSERT OR IGNORE INTO siem_traffic VALUES(1,'{}',0,'');
		CREATE TABLE IF NOT EXISTS siem_traffic_queue(
		seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, body BLOB NOT NULL);`)
	return err
}

func (s *Store) SIEMTrafficStats(ctx context.Context) (SIEMTrafficStats, error) {
	var stats SIEMTrafficStats
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM siem_traffic_queue),evicted,last_sent
		FROM siem_traffic WHERE id=1`).Scan(&stats.Queued, &stats.Evicted, &stats.LastSent)
	return stats, err
}

func (s *Store) EnqueueSIEMTraffic(ctx context.Context, events []traffic.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled bool
	var rawFilter string
	if err := tx.QueryRowContext(ctx, `SELECT s.enabled,t.filter FROM siem AS s
		JOIN siem_traffic AS t ON s.id=t.id WHERE s.id=1`).Scan(&enabled, &rawFilter); err != nil || !enabled {
		return err
	}
	var filter traffic.ExportFilter
	if err := json.Unmarshal([]byte(rawFilter), &filter); err != nil {
		return err
	}
	if !filter.Enabled() {
		return nil
	}
	match, err := filter.Compile()
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT OR IGNORE INTO siem_traffic_queue(event_id,body) VALUES(?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	queued := false
	for _, event := range events {
		if event.EventID == "" || !match(event) {
			continue
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err = stmt.ExecContext(ctx, event.EventID, raw); err != nil {
			return err
		}
		queued = true
	}
	if !queued {
		return nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM siem_traffic_queue WHERE seq IN (
		SELECT seq FROM siem_traffic_queue ORDER BY seq
		LIMIT (SELECT max(count(*)-?,0) FROM siem_traffic_queue))`, trafficQueueLimit)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE siem_traffic SET evicted=evicted+? WHERE id=1", n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PeekSIEMTraffic(ctx context.Context) (traffic.Batch, error) {
	var batch traffic.Batch
	rows, err := s.db.QueryContext(ctx, "SELECT seq,body FROM siem_traffic_queue ORDER BY seq LIMIT ?", SIEMTrafficBatch)
	if err != nil {
		return batch, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var event traffic.Event
		if err = rows.Scan(&batch.Cursor, &raw); err != nil {
			return batch, err
		}
		if err = json.Unmarshal(raw, &event); err != nil {
			return batch, err
		}
		batch.Events = append(batch.Events, event)
	}
	return batch, rows.Err()
}

func (s *Store) AckSIEMTraffic(ctx context.Context, revision, cursor int64, sent bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM siem_traffic_queue WHERE seq<=?
		AND EXISTS(SELECT 1 FROM siem WHERE id=1 AND revision=?)`, cursor, revision)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if sent && n > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE siem_traffic SET last_sent=? WHERE id=1", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
