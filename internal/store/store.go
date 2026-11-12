package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/gfw/internal/policy"
	_ "modernc.org/sqlite"
)

var ErrConflict = errors.New("ревизия изменилась; обновите данные перед сохранением")

type Store struct{ db *sql.DB }
type Snapshot struct {
	Revision  int64         `json:"revision"`
	Config    policy.Config `json:"config"`
	UpdatedAt string        `json:"updated_at"`
}
type Event struct {
	ID       int64  `json:"id"`
	At       string `json:"at"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Revision int64  `json:"revision"`
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
 INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
 CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, body TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, revision INTEGER NOT NULL);`)
	if err != nil {
		return fail(err)
	}
	var version int
	if err = db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version < 1 || version > 10 {
		return fail(fmt.Errorf("unsupported schema version %d", version))
	}
	raw, _ := json.Marshal(policy.Default())
	_, err = db.Exec("INSERT OR IGNORE INTO config VALUES(1,1,?,?)", string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fail(err)
	}
	if err = s.initNetwork(); err != nil {
		return fail(err)
	}
	if err = s.initIPsec(); err != nil {
		return fail(err)
	}
	if err = s.initOpenVPNRuntime(); err != nil {
		return fail(err)
	}
	if err = s.initOpenVPN(); err != nil {
		return fail(err)
	}
	if err = s.initWireGuard(); err != nil {
		return fail(err)
	}
	if err = s.initServices(); err != nil {
		return fail(err)
	}
	if err = s.initFeed(); err != nil {
		return fail(err)
	}
	if err = s.initIDS(); err != nil {
		return fail(err)
	}
	if err = s.initFESS(); err != nil {
		return fail(err)
	}
	if version < 10 {
		if _, err = db.Exec("UPDATE schema_version SET version=10 WHERE version<10"); err != nil {
			return fail(err)
		}
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) LogAudit(ctx context.Context, action string, revision int64) error {
	return s.LogAuditActor(ctx, "admin", action, revision)
}

func (s *Store) LogAuditActor(ctx context.Context, actor, action string, revision int64) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), actor, action, revision)
	return err
}
func (s *Store) Read(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	var body string
	err := s.db.QueryRowContext(ctx, "SELECT revision,body,updated_at FROM config WHERE id=1").Scan(&out.Revision, &body, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(body), &out.Config)
	out.Config = policy.Canonical(out.Config)
	return out, err
}
func (s *Store) Save(ctx context.Context, revision int64, c policy.Config) (Snapshot, error) {
	c = policy.Canonical(c)
	if err := policy.Validate(c); err != nil {
		return Snapshot{}, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return Snapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "UPDATE config SET revision=revision+1,body=?,updated_at=? WHERE id=1 AND revision=?", string(raw), at, revision)
	if err != nil {
		return Snapshot{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Snapshot{}, err
	}
	if n != 1 {
		return Snapshot{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)", at, "admin", "policy.draft.save", revision+1)
	if err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Revision: revision + 1, Config: c, UpdatedAt: at}, nil
}
func (s *Store) Audit(ctx context.Context) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,actor,action,revision FROM audit ORDER BY id DESC LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Revision); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
