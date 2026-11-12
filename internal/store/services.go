package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/services"
)

type ServicesSnapshot struct {
	Revision  int64           `json:"revision"`
	Config    services.Config `json:"config"`
	UpdatedAt string          `json:"updated_at"`
}

func (s *Store) initServices() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS services_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(services.Default())
	_, err = s.db.Exec("INSERT OR IGNORE INTO services_config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ReadServices(ctx context.Context) (ServicesSnapshot, error) {
	var out ServicesSnapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM services_config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	return out, err
}
func (s *Store) SaveServices(ctx context.Context, revision int64, c services.Config) (ServicesSnapshot, error) {
	if err := services.Validate(c); err != nil {
		return ServicesSnapshot{}, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ServicesSnapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServicesSnapshot{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, "UPDATE services_config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), now, revision)
	if err != nil {
		return ServicesSnapshot{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ServicesSnapshot{}, err
	}
	if n != 1 {
		return ServicesSnapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", now, "admin", "services.draft.save", revision+1)
	if err != nil {
		return ServicesSnapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return ServicesSnapshot{}, err
	}
	return ServicesSnapshot{revision + 1, c, now}, nil
}
