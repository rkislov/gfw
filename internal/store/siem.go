package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rkislov/gfw/internal/traffic"
)

type SIEM struct {
	Traffic     *traffic.ExportFilter `json:"traffic"`
	Revision    int64                 `json:"revision"`
	Enabled     bool                  `json:"enabled"`
	Address     string                `json:"address"`
	Transport   string                `json:"transport"`
	CA          string                `json:"ca_pem"`
	AuditCursor int64                 `json:"audit_cursor"`
	IDSCursor   int64                 `json:"ids_cursor"`
	LastSent    string                `json:"last_sent,omitempty"`
}

func (s *Store) initSIEM() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS siem(
		id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, enabled INTEGER NOT NULL,
		address TEXT NOT NULL, transport TEXT NOT NULL, ca TEXT NOT NULL,
		audit_cursor INTEGER NOT NULL, ids_cursor INTEGER NOT NULL, last_sent TEXT NOT NULL);
		INSERT OR IGNORE INTO siem VALUES(1,1,0,'','tls','',0,0,'');`)
	if err != nil {
		return err
	}
	return s.initSIEMTraffic()
}

func (s *Store) ReadSIEM(ctx context.Context) (SIEM, error) {
	var cfg SIEM
	var filter string
	err := s.db.QueryRowContext(ctx, `SELECT s.revision,s.enabled,s.address,s.transport,s.ca,s.audit_cursor,s.ids_cursor,s.last_sent,t.filter
		FROM siem AS s JOIN siem_traffic AS t ON s.id=t.id WHERE s.id=1`).
		Scan(&cfg.Revision, &cfg.Enabled, &cfg.Address, &cfg.Transport, &cfg.CA, &cfg.AuditCursor, &cfg.IDSCursor, &cfg.LastSent, &filter)
	if err != nil {
		return cfg, err
	}
	cfg.Traffic = &traffic.ExportFilter{}
	err = json.Unmarshal([]byte(filter), cfg.Traffic)
	return cfg, err
}

func (s *Store) SaveSIEM(ctx context.Context, cfg SIEM, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE siem SET revision=revision+1,enabled=?,address=?,transport=?,ca=?
		WHERE id=1 AND revision=?`, cfg.Enabled, cfg.Address, cfg.Transport, cfg.CA, cfg.Revision)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrConflict
	}
	if cfg.Traffic != nil {
		raw, err := json.Marshal(cfg.Traffic)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE siem_traffic SET filter=? WHERE id=1", string(raw)); err != nil {
			return err
		}
		if !cfg.Traffic.Enabled() {
			if _, err = tx.ExecContext(ctx, "DELETE FROM siem_traffic_queue"); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(at,actor,action,revision) VALUES(?,?,?,?)",
		time.Now().UTC().Format(time.RFC3339Nano), actor, "siem.config.save", cfg.Revision+1); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AdvanceSIEM(ctx context.Context, revision, auditID, idsID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE siem SET audit_cursor=max(audit_cursor,?), ids_cursor=max(ids_cursor,?), last_sent=?
		WHERE id=1 AND revision=?`, auditID, idsID, time.Now().UTC().Format(time.RFC3339Nano), revision)
	return err
}

func (s *Store) AuditAfter(ctx context.Context, id int64) ([]Event, error) {
	return s.readAudit(ctx, "SELECT id,at,actor,action,revision FROM audit WHERE id>? ORDER BY id LIMIT 100", id)
}
