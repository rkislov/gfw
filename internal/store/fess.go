package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/fess"
)

type FESSSnapshot struct {
	Revision int64       `json:"revision"`
	Config   fess.Config `json:"config"`
}

func (s *Store) initFESS() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS fess_config(
	id INTEGER PRIMARY KEY CHECK(id IN (1,2)), revision INTEGER NOT NULL, body TEXT NOT NULL);
	INSERT OR IGNORE INTO fess_config VALUES(1,1,'{"sites":[]}'),(2,0,'{"sites":[]}');
	CREATE TABLE IF NOT EXISTS fess_events(id INTEGER PRIMARY KEY AUTOINCREMENT,body TEXT NOT NULL);`)
	return err
}

func (s *Store) ReadFESS(ctx context.Context, confirmed bool) (FESSSnapshot, error) {
	id := 1
	if confirmed {
		id = 2
	}
	var v FESSSnapshot
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT revision,body FROM fess_config WHERE id=?", id).Scan(&v.Revision, &raw)
	if err == nil {
		err = json.Unmarshal(raw, &v.Config)
	}
	return v, err
}

func (s *Store) SaveFESS(ctx context.Context, v FESSSnapshot, confirmed bool) (FESSSnapshot, error) {
	raw, err := json.Marshal(v.Config)
	if err != nil {
		return v, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	action := "fess.confirm"
	if confirmed {
		_, err = tx.ExecContext(ctx, "UPDATE fess_config SET revision=?, body=? WHERE id=2", v.Revision, string(raw))
	} else {
		action = "fess.draft.save"
		var result sql.Result
		result, err = tx.ExecContext(ctx, "UPDATE fess_config SET revision=revision+1,body=? WHERE id=1 AND revision=?", string(raw), v.Revision)
		if err == nil {
			var n int64
			n, err = result.RowsAffected()
			if err == nil && n != 1 {
				return v, ErrConflict
			}
		}
		v.Revision++
	}
	if err != nil {
		return v, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), "admin", action, v.Revision); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

func (s *Store) WriteFESSEvents(ctx context.Context, events []fess.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	for _, event := range events {
		body, err := json.Marshal(event)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO fess_events(body) VALUES(?)", string(body))
		if err != nil {
			return err
		}
		last, err = result.LastInsertId()
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM fess_events WHERE id<=?", last-2000); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FESSEvents(ctx context.Context) ([]fess.Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT body FROM fess_events ORDER BY id DESC LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []fess.Event{}
	for rows.Next() {
		var raw []byte
		var event fess.Event
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
