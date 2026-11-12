package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/wireguard"
)

type WireGuardSnapshot struct {
	Revision  int64            `json:"revision"`
	Config    wireguard.Config `json:"config"`
	UpdatedAt string           `json:"updated_at"`
}

func (s *Store) initWireGuard() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS wireguard_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(wireguard.Empty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO wireguard_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadWireGuard(ctx context.Context) (WireGuardSnapshot, error) {
	var out WireGuardSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM wireguard_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	return out, err
}
func (s *Store) SaveWireGuard(ctx context.Context, revision int64, c wireguard.Config) (WireGuardSnapshot, error) {
	if err := wireguard.Validate(c); err != nil {
		return WireGuardSnapshot{}, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE wireguard_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	if n != 1 {
		return WireGuardSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "wireguard.draft.save", revision+1)
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return WireGuardSnapshot{}, err
	}
	return WireGuardSnapshot{revision + 1, c, now}, nil
}
