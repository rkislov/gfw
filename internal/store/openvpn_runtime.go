package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/openvpn"
)

type OpenVPNRuntimeSnapshot struct {
	Revision  int64                 `json:"revision"`
	Config    openvpn.RuntimeConfig `json:"config"`
	UpdatedAt string                `json:"updated_at"`
}

func (s *Store) initOpenVPNRuntime() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS openvpn_runtime_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(openvpn.RuntimeEmpty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO openvpn_runtime_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadOpenVPNRuntime(ctx context.Context) (OpenVPNRuntimeSnapshot, error) {
	var out OpenVPNRuntimeSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM openvpn_runtime_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	if out.Config.Instances == nil {
		out.Config.Instances = []openvpn.Instance{}
	}
	return out, err
}
func (s *Store) SaveOpenVPNRuntime(ctx context.Context, revision int64, c openvpn.RuntimeConfig) (OpenVPNRuntimeSnapshot, error) {
	if err := openvpn.ValidateRuntime(c); err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	if c.Instances == nil {
		c.Instances = []openvpn.Instance{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE openvpn_runtime_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	if n != 1 {
		return OpenVPNRuntimeSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "openvpn.runtime.draft.save", revision+1)
	if err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return OpenVPNRuntimeSnapshot{}, err
	}
	return OpenVPNRuntimeSnapshot{revision + 1, c, now}, nil
}
