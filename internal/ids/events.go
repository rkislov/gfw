package ids

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

const eventLimit = 20000

type Alert struct {
	ID       int64  `json:"id"`
	At       string `json:"at"`
	IFace    string `json:"interface"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	SID      int64  `json:"sid"`
	Severity int    `json:"severity"`
	Message  string `json:"message"`
	RuleHash string `json:"rule_sha256"`
	Action   string `json:"action"`
}

func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= limit {
		return s
	}
	end := 0
	for i := range s {
		if i > limit {
			break
		}
		end = i
	}
	return s[:end]
}

func parseAlert(raw []byte, hash string) (Alert, bool) {
	var e struct {
		EventType  string `json:"event_type"`
		Timestamp  string `json:"timestamp"`
		IFace      string `json:"in_iface"`
		Source     string `json:"src_ip"`
		Target     string `json:"dest_ip"`
		SourcePort int    `json:"src_port"`
		TargetPort int    `json:"dest_port"`
		Protocol   string `json:"proto"`
		Alert      struct {
			SID      int64  `json:"signature_id"`
			Severity int    `json:"severity"`
			Message  string `json:"signature"`
			Action   string `json:"action"`
		} `json:"alert"`
	}
	if json.Unmarshal(raw, &e) != nil || e.EventType != "alert" || e.Alert.SID <= 0 {
		return Alert{}, false
	}
	src, se := netip.ParseAddr(e.Source)
	dst, de := netip.ParseAddr(e.Target)
	at, err := time.Parse("2006-01-02T15:04:05.999999999-0700", e.Timestamp)
	if err != nil {
		at, err = time.Parse(time.RFC3339Nano, e.Timestamp)
	}
	if se != nil || de != nil || err != nil || (e.IFace != "" && !interfaceName.MatchString(e.IFace)) ||
		e.SourcePort < 0 || e.SourcePort > 65535 || e.TargetPort < 0 || e.TargetPort > 65535 {
		return Alert{}, false
	}
	action := "allowed"
	if e.Alert.Action == "blocked" {
		action = "blocked"
	}
	return Alert{Action: action, At: at.UTC().Format(time.RFC3339Nano), IFace: e.IFace, Src: src.String(), Dst: dst.String(),
		SrcPort: e.SourcePort, DstPort: e.TargetPort, Protocol: cleanText(e.Protocol, 16),
		SID: e.Alert.SID, Severity: e.Alert.Severity, Message: cleanText(e.Alert.Message, 384), RuleHash: hash}, true
}

func openEvents(root string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filepath.Join(root, "alerts.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=2500;
PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=2097152; PRAGMA max_page_count=16384;
CREATE TABLE IF NOT EXISTS alerts(
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, iface TEXT, src TEXT, dst TEXT,
 src_port INTEGER, dst_port INTEGER, proto TEXT, sid INTEGER, severity INTEGER, msg TEXT, rule_hash TEXT);`)
	if err == nil {
		err = migrateEvents(db)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrateEvents(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == 0 {
		if _, err = tx.Exec("ALTER TABLE alerts ADD COLUMN action TEXT NOT NULL DEFAULT 'allowed'; PRAGMA user_version=1;"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func writeEvents(db *sql.DB, events []Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO alerts(at,iface,src,dst,src_port,dst_port,proto,sid,severity,msg,rule_hash,action) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	var last int64
	for _, e := range events {
		result, err := stmt.ExecContext(ctx, e.At, e.IFace, e.Src, e.Dst, e.SrcPort, e.DstPort,
			e.Protocol, e.SID, e.Severity, e.Message, e.RuleHash, e.Action)
		if err != nil {
			return err
		}
		last, err = result.LastInsertId()
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM alerts WHERE id<=?", last-eventLimit); err != nil {
		return err
	}
	return tx.Commit()
}

func readEvents(db *sql.DB, limit int, before int64) ([]Alert, error) {
	if before > 0 {
		return queryEvents(db, " WHERE id<? ORDER BY id DESC LIMIT ?", before, limit)
	}
	return queryEvents(db, " ORDER BY id DESC LIMIT ?", limit)
}

func queryEvents(db *sql.DB, order string, args ...any) ([]Alert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const fields = "SELECT id,at,iface,src,dst,src_port,dst_port,proto,sid,severity,msg,rule_hash,action FROM alerts"
	rows, err := db.QueryContext(ctx, fields+order, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var e Alert
		if err = rows.Scan(&e.ID, &e.At, &e.IFace, &e.Src, &e.Dst, &e.SrcPort, &e.DstPort, &e.Protocol,
			&e.SID, &e.Severity, &e.Message, &e.RuleHash, &e.Action); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
