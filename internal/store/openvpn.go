package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/openvpn"
)

type OpenVPNSnapshot struct {
	Revision  int64          `json:"revision"`
	Config    openvpn.Config `json:"config"`
	UpdatedAt string         `json:"updated_at"`
}

func (s *Store) initOpenVPN() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS openvpn_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(openvpn.Empty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO openvpn_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadOpenVPN(ctx context.Context) (OpenVPNSnapshot, error) {
	var out OpenVPNSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM openvpn_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	if out.Config.Profiles == nil {
		out.Config.Profiles = []openvpn.Profile{}
	}
	return out, err
}
func (s *Store) SaveOpenVPN(ctx context.Context, revision int64, c openvpn.Config) (OpenVPNSnapshot, error) {
	if err := openvpn.Validate(c); err != nil {
		return OpenVPNSnapshot{}, err
	}
	if c.Profiles == nil {
		c.Profiles = []openvpn.Profile{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return OpenVPNSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OpenVPNSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE openvpn_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return OpenVPNSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return OpenVPNSnapshot{}, err
	}
	if n != 1 {
		return OpenVPNSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "openvpn.draft.save", revision+1)
	if err != nil {
		return OpenVPNSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return OpenVPNSnapshot{}, err
	}
	return OpenVPNSnapshot{revision + 1, c, now}, nil
}
