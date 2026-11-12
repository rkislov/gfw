package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/ids"
)

type IDSSnapshot struct {
	Revision  int64      `json:"revision"`
	Config    ids.Config `json:"config"`
	UpdatedAt string     `json:"updated_at"`
}

func (s *Store) initIDS() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ids_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(ids.Empty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO ids_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadIDS(ctx context.Context) (IDSSnapshot, error) {
	var out IDSSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM ids_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	if out.Config.Interfaces == nil {
		out.Config.Interfaces = []string{}
	}
	if out.Config.HomeNet == nil {
		out.Config.HomeNet = []string{}
	}
	return out, err
}
func (s *Store) SaveIDS(ctx context.Context, revision int64, c ids.Config) (IDSSnapshot, error) {
	if err := ids.Validate(c); err != nil {
		return IDSSnapshot{}, err
	}
	if c.Interfaces == nil {
		c.Interfaces = []string{}
	}
	if c.HomeNet == nil {
		c.HomeNet = []string{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return IDSSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IDSSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE ids_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return IDSSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return IDSSnapshot{}, err
	}
	if n != 1 {
		return IDSSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "ids.draft.save", revision+1)
	if err != nil {
		return IDSSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return IDSSnapshot{}, err
	}
	return IDSSnapshot{revision + 1, c, now}, nil
}
