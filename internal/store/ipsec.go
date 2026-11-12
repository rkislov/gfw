package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/ipsec"
)

type IPsecSnapshot struct {
	Revision  int64        `json:"revision"`
	Config    ipsec.Config `json:"config"`
	UpdatedAt string       `json:"updated_at"`
}

func (s *Store) initIPsec() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ipsec_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(ipsec.Empty())
	_, err = s.db.Exec("INSERT OR IGNORE INTO ipsec_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadIPsec(ctx context.Context) (IPsecSnapshot, error) {
	var out IPsecSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM ipsec_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	if out.Config.Tunnels == nil {
		out.Config.Tunnels = []ipsec.Tunnel{}
	}
	return out, err
}
func (s *Store) SaveIPsec(ctx context.Context, revision int64, c ipsec.Config) (IPsecSnapshot, error) {
	if err := ipsec.Validate(c); err != nil {
		return IPsecSnapshot{}, err
	}
	if c.Tunnels == nil {
		c.Tunnels = []ipsec.Tunnel{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return IPsecSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IPsecSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE ipsec_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return IPsecSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return IPsecSnapshot{}, err
	}
	if n != 1 {
		return IPsecSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "ipsec.draft.save", revision+1)
	if err != nil {
		return IPsecSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return IPsecSnapshot{}, err
	}
	return IPsecSnapshot{revision + 1, c, now}, nil
}
