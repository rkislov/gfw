package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/netconfig"
)

type NetworkSnapshot struct {
	Revision  int64            `json:"revision"`
	Config    netconfig.Config `json:"config"`
	UpdatedAt string           `json:"updated_at"`
}

func (s *Store) initNetwork() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS network_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(netconfig.Empty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO network_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadNetwork(ctx context.Context) (NetworkSnapshot, error) {
	var out NetworkSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM network_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	return out, err
}
func (s *Store) SaveNetwork(ctx context.Context, revision int64, c netconfig.Config) (NetworkSnapshot, error) {
	c = netconfig.Canonical(c)
	if err := netconfig.Validate(c); err != nil {
		return NetworkSnapshot{}, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE network_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return NetworkSnapshot{}, err
	}
	if n != 1 {
		return NetworkSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "network.draft.save", revision+1)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return NetworkSnapshot{}, err
	}
	return NetworkSnapshot{revision + 1, c, now}, nil
}
