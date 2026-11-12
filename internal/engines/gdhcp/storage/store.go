// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/model"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Catalog is the configured VLAN, subnet, relay and reservation set.
type Catalog struct {
	VLANs        []model.VLAN
	Subnets      []model.Subnet
	Relays       []model.Relay
	Reservations []model.Reservation
}

// Store is the lease and catalog persistence port.
type Store interface {
	Close() error
	Ping(ctx context.Context) error
	UpsertLease(ctx context.Context, l model.Lease) error
	GetLease(ctx context.Context, ip string) (model.Lease, error)
	ListLeases(ctx context.Context, f model.LeaseFilter) ([]model.Lease, int, error)
	DeleteLease(ctx context.Context, ip string) error
	ActiveLeases(ctx context.Context, now time.Time) ([]model.Lease, error)
	ExpireLeases(ctx context.Context, now time.Time) (int, error)
	ReplaceCatalog(ctx context.Context, cat Catalog) error
	ListVLANs(ctx context.Context) ([]model.VLAN, error)
	ListSubnets(ctx context.Context) ([]model.Subnet, error)
	ListRelays(ctx context.Context) ([]model.Relay, error)
	ListReservations(ctx context.Context) ([]model.Reservation, error)
	CreateReservation(ctx context.Context, r model.Reservation) (model.Reservation, error)
	DeleteReservation(ctx context.Context, id int64) error
}

// Open creates a SQLite or PostgreSQL store and applies migrations.
func Open(ctx context.Context, driver, dsn string) (Store, error) {
	managedCheckpoint := driver == "sqlite" && !strings.Contains(dsn, "_pragma") && !strings.Contains(dsn, ":memory:") && !strings.Contains(dsn, "mode=memory")
	sqlDriver := driver
	switch driver {
	case "sqlite":
		sqlDriver = "sqlite"
		dsn = sqliteDSN(dsn)
	case "postgres":
		sqlDriver = "pgx"
	default:
		return nil, fmt.Errorf("storage: unsupported driver %q", driver)
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(16)
	}
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &SQLStore{db: db, postgres: driver == "postgres"}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.prepareLeaseStatements(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if managedCheckpoint {
		if err := s.startCheckpoint(ctx, dsn); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return s, nil
}

func sqliteDSN(dsn string) string {
	if strings.HasPrefix(dsn, "file:") || strings.Contains(dsn, ":memory:") {
		if !strings.Contains(dsn, "_pragma") {
			sep := "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
			dsn += sep + sqlitePragmas
		}
		return dsn
	}
	if err := os.MkdirAll(filepath.Dir(dsn), 0o750); err != nil && filepath.Dir(dsn) != "." {
		// The caller surfaces a later open error if the directory is unusable.
	}
	return "file:" + dsn + "?" + sqlitePragmas
}

const sqlitePragmas = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=wal_autocheckpoint(16384)&_pragma=cache_size(-32768)"

// SQLStore speaks database/sql to SQLite and PostgreSQL.
type SQLStore struct {
	db               *sql.DB
	postgres         bool
	renewStmt        *sql.Stmt
	getStmt          *sql.Stmt
	checkpointDB     *sql.DB
	checkpointCancel context.CancelFunc
	checkpointDone   chan struct{}
	closeOnce        sync.Once
	closeErr         error
}

func (s *SQLStore) Close() error {
	s.closeOnce.Do(func() {
		if s.checkpointCancel != nil {
			s.checkpointCancel()
			<-s.checkpointDone
		}
		s.closeErr = s.db.Close()
		if s.checkpointDB != nil {
			s.closeErr = errors.Join(s.closeErr, s.checkpointDB.Close())
		}
	})
	return s.closeErr
}

func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLStore) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *SQLStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("storage: migrate: %w", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range schemaStmts() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("storage: schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)`), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func schemaStmts() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS vlans (
    id INTEGER PRIMARY KEY,
    name TEXT,
    interface TEXT,
    priority INTEGER,
    source TEXT,
    subnet_id TEXT
)`,
		`CREATE TABLE IF NOT EXISTS subnets (
    id TEXT PRIMARY KEY,
    network TEXT NOT NULL,
    range_start TEXT,
    range_end TEXT,
    gateway TEXT,
    vlan_id INTEGER,
    domain TEXT,
    dns TEXT,
    options TEXT,
    lease_seconds INTEGER
)`,
		`CREATE TABLE IF NOT EXISTS relays (
    giaddr TEXT PRIMARY KEY,
    remote_id TEXT,
    vendor TEXT,
    trusted INTEGER NOT NULL DEFAULT 0,
    parser_name TEXT,
    vlan_id INTEGER,
    subnet_id TEXT,
    created_at TEXT
)`,
		`CREATE TABLE IF NOT EXISTS leases (
    ip TEXT PRIMARY KEY,
    mac TEXT NOT NULL,
    client_id TEXT,
    hostname TEXT,
    subnet_id TEXT,
    vlan_id INTEGER,
    giaddr TEXT,
    circuit_id TEXT,
    remote_id TEXT,
    link_select TEXT,
    state TEXT,
    expires_at TEXT,
    created_at TEXT
)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_mac ON leases(mac)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_vlan ON leases(vlan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_giaddr ON leases(giaddr)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_subnet ON leases(subnet_id)`,
		`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY,
    mac TEXT,
    client_id TEXT,
    ip TEXT NOT NULL,
    hostname TEXT,
    subnet_id TEXT
)`,
		`CREATE INDEX IF NOT EXISTS idx_reservations_mac ON reservations(mac)`,
		`CREATE INDEX IF NOT EXISTS idx_reservations_ip ON reservations(ip)`,
	}
}

// Renew the same binding without rewriting the MAC/subnet/VLAN indexes.
// Metadata may change when a client renews directly after allocation by relay.
const renewSQL = `UPDATE leases SET hostname = ?, giaddr = ?, circuit_id = ?, remote_id = ?, link_select = ?, state = ?, expires_at = ?
WHERE ip = ? AND mac = ? AND client_id IS NOT DISTINCT FROM ? AND subnet_id IS NOT DISTINCT FROM ? AND vlan_id IS NOT DISTINCT FROM ?`
const getLeaseSQL = `SELECT ip, mac, client_id, hostname, subnet_id, vlan_id, giaddr, circuit_id, remote_id, link_select, state, expires_at, created_at FROM leases WHERE ip = ?`

func (s *SQLStore) prepareLeaseStatements(ctx context.Context) error {
	var err error
	s.renewStmt, err = s.db.PrepareContext(ctx, s.q(renewSQL))
	if err != nil {
		return err
	}
	s.getStmt, err = s.db.PrepareContext(ctx, s.q(getLeaseSQL))
	return err
}

func renewalArgs(l model.Lease) []any {
	return []any{nullStr(l.Hostname), nullStr(l.GIAddr), nullStr(l.CircuitID), nullStr(l.RemoteID), nullStr(l.LinkSelect), l.State,
		l.ExpiresAt.UTC().Format(time.RFC3339Nano), l.IP, l.MAC, nullStr(l.ClientID), nullStr(l.SubnetID), nullInt(l.VLANID)}
}

func (s *SQLStore) UpsertLease(ctx context.Context, l model.Lease) error {
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	// A single autocommit UPDATE is already atomic. A reply is allowed only
	// after Exec returns, under the same WAL/synchronous policy as before.
	if l.GIAddr == "" && s.leaseTransaction(ctx) == nil {
		res, err := s.renewStmt.ExecContext(ctx, renewalArgs(l)...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}
	if tx := s.leaseTransaction(ctx); tx != nil {
		return s.upsertInTransaction(ctx, tx, l)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.upsertInTransaction(ctx, tx, l); err != nil {
		return err
	}
	return commitLeaseTx(tx)
}

func (s *SQLStore) upsertInTransaction(ctx context.Context, tx *sql.Tx, l model.Lease) error {
	if l.GIAddr != "" {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO relays(giaddr, trusted, created_at) VALUES (?, 0, ?) ON CONFLICT(giaddr) DO NOTHING`), l.GIAddr, l.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	{
		res, err := tx.StmtContext(ctx, s.renewStmt).ExecContext(ctx, renewalArgs(l)...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}
	_, err := tx.ExecContext(ctx, s.q(`
INSERT INTO leases(ip, mac, client_id, hostname, subnet_id, vlan_id, giaddr, circuit_id, remote_id, link_select, state, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    mac = excluded.mac,
    client_id = excluded.client_id,
    hostname = excluded.hostname,
    subnet_id = excluded.subnet_id,
    vlan_id = excluded.vlan_id,
    giaddr = excluded.giaddr,
    circuit_id = excluded.circuit_id,
    remote_id = excluded.remote_id,
    link_select = excluded.link_select,
    state = excluded.state,
    expires_at = excluded.expires_at`),
		l.IP, l.MAC, nullStr(l.ClientID), nullStr(l.Hostname), nullStr(l.SubnetID), nullInt(l.VLANID), nullStr(l.GIAddr),
		nullStr(l.CircuitID), nullStr(l.RemoteID), nullStr(l.LinkSelect), l.State,
		l.ExpiresAt.UTC().Format(time.RFC3339Nano), l.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return nil
}
func (s *SQLStore) GetLease(ctx context.Context, ip string) (model.Lease, error) {
	if tx := s.leaseTransaction(ctx); tx != nil {
		return scanLease(tx.StmtContext(ctx, s.getStmt).QueryRowContext(ctx, ip))
	}
	return scanLease(s.getStmt.QueryRowContext(ctx, ip))
}

func (s *SQLStore) ListLeases(ctx context.Context, f model.LeaseFilter) ([]model.Lease, int, error) {
	where, args := leaseWhere(f)
	var total int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM leases `+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	qargs := append(append([]any{}, args...), limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT ip, mac, client_id, hostname, subnet_id, vlan_id, giaddr, circuit_id, remote_id, link_select, state, expires_at, created_at FROM leases `+where+` ORDER BY ip LIMIT ? OFFSET ?`), qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list, err := scanLeases(rows)
	return list, total, err
}

func leaseWhere(f model.LeaseFilter) (string, []any) {
	var parts []string
	var args []any
	if f.AllowedSubnets != nil {
		if len(f.AllowedSubnets) == 0 {
			parts = append(parts, "1 = 0")
		} else {
			placeholders := make([]string, len(f.AllowedSubnets))
			for i, id := range f.AllowedSubnets {
				placeholders[i] = "?"
				args = append(args, id)
			}
			parts = append(parts, "subnet_id IN ("+strings.Join(placeholders, ",")+")")
		}
	}
	if f.AllowedVLANs != nil {
		if len(f.AllowedVLANs) == 0 {
			parts = append(parts, "vlan_id IS NULL")
		} else {
			placeholders := make([]string, len(f.AllowedVLANs))
			for i, id := range f.AllowedVLANs {
				placeholders[i] = "?"
				args = append(args, id)
			}
			parts = append(parts, "(vlan_id IS NULL OR vlan_id IN ("+strings.Join(placeholders, ",")+"))")
		}
	}
	if f.VLAN != nil {
		parts = append(parts, "vlan_id = ?")
		args = append(args, *f.VLAN)
	}
	if f.SubnetID != "" {
		parts = append(parts, "subnet_id = ?")
		args = append(args, f.SubnetID)
	}
	if f.GIAddr != "" {
		parts = append(parts, "giaddr = ?")
		args = append(args, f.GIAddr)
	}
	if f.State != "" {
		parts = append(parts, "state = ?")
		args = append(args, f.State)
	}
	if f.Query != "" {
		like := "%" + f.Query + "%"
		parts = append(parts, "(ip LIKE ? OR mac LIKE ? OR hostname LIKE ? OR circuit_id LIKE ?)")
		args = append(args, like, like, like, like)
	}
	if len(parts) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(parts, " AND "), args
}

func (s *SQLStore) DeleteLease(ctx context.Context, ip string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM leases WHERE ip = ?`), ip)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) ActiveLeases(ctx context.Context, now time.Time) ([]model.Lease, error) {
	var query interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	} = s.db
	if tx := s.leaseTransaction(ctx); tx != nil {
		query = tx
	}
	rows, err := query.QueryContext(ctx, s.q(`SELECT ip, mac, client_id, hostname, subnet_id, vlan_id, giaddr, circuit_id, remote_id, link_select, state, expires_at, created_at FROM leases WHERE state IN ('offered','bound','declined') AND expires_at > ?`), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanLeases(rows)
}

func (s *SQLStore) ExpireLeases(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE leases SET state = 'expired' WHERE state IN ('offered','bound','declined') AND expires_at <= ?`), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLStore) ReplaceCatalog(ctx context.Context, cat Catalog) error {
	vlans, subnets, relays, reservations := cat.VLANs, cat.Subnets, cat.Relays, cat.Reservations
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{`DELETE FROM reservations`, `DELETE FROM relays`, `DELETE FROM subnets`, `DELETE FROM vlans`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, v := range vlans {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO vlans(id, name, interface, priority, source, subnet_id) VALUES (?, ?, ?, ?, ?, ?)`), v.ID, v.Name, v.Interface, v.Priority, v.Source, v.SubnetID); err != nil {
			return err
		}
	}
	for _, sub := range subnets {
		dns, _ := json.Marshal(sub.DNS)
		opts, _ := json.Marshal(sub.Options)
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO subnets(id, network, range_start, range_end, gateway, vlan_id, domain, dns, options, lease_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			sub.ID, sub.Network, sub.RangeStart, sub.RangeEnd, sub.Gateway, nullInt(sub.VLANID), sub.Domain, string(dns), string(opts), sub.LeaseSec); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, r := range relays {
		trusted := 0
		if r.Trusted {
			trusted = 1
		}
		created := now
		if !r.CreatedAt.IsZero() {
			created = r.CreatedAt.UTC().Format(time.RFC3339Nano)
		}
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO relays(giaddr, remote_id, vendor, trusted, parser_name, vlan_id, subnet_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			r.GIAddr, r.RemoteID, r.Vendor, trusted, r.ParserName, nullInt(r.VLANID), r.SubnetID, created); err != nil {
			return err
		}
	}
	for _, r := range reservations {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO reservations(mac, client_id, ip, hostname, subnet_id) VALUES (?, ?, ?, ?, ?)`),
			nullStr(r.MAC), nullStr(r.ClientID), r.IP, nullStr(r.Hostname), r.SubnetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListVLANs(ctx context.Context) ([]model.VLAN, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, interface, priority, source, subnet_id FROM vlans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VLAN
	for rows.Next() {
		var v model.VLAN
		if err := rows.Scan(&v.ID, &v.Name, &v.Interface, &v.Priority, &v.Source, &v.SubnetID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListSubnets(ctx context.Context) ([]model.Subnet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, network, range_start, range_end, gateway, vlan_id, domain, dns, options, lease_seconds FROM subnets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Subnet
	for rows.Next() {
		sub, err := scanSubnet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListRelays(ctx context.Context) ([]model.Relay, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT giaddr, remote_id, vendor, trusted, parser_name, vlan_id, subnet_id, created_at FROM relays ORDER BY giaddr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Relay
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListReservations(ctx context.Context) ([]model.Reservation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, mac, client_id, ip, hostname, subnet_id FROM reservations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Reservation
	for rows.Next() {
		r, err := scanReservation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateReservation(ctx context.Context, r model.Reservation) (model.Reservation, error) {
	row := s.db.QueryRowContext(ctx, s.q(`INSERT INTO reservations(mac, client_id, ip, hostname, subnet_id) VALUES (?, ?, ?, ?, ?) RETURNING id`),
		nullStr(r.MAC), nullStr(r.ClientID), r.IP, nullStr(r.Hostname), r.SubnetID)
	if err := row.Scan(&r.ID); err != nil {
		return model.Reservation{}, err
	}
	return r, nil
}

func (s *SQLStore) DeleteReservation(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM reservations WHERE id = ?`), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanLease(row scanner) (model.Lease, error) {
	var l model.Lease
	var clientID, hostname, subnet, giaddr, circuit, remote, link, exp, created sql.NullString
	var vlan sql.NullInt64
	if err := row.Scan(&l.IP, &l.MAC, &clientID, &hostname, &subnet, &vlan, &giaddr, &circuit, &remote, &link, &l.State, &exp, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Lease{}, ErrNotFound
		}
		return model.Lease{}, err
	}
	l.ClientID = clientID.String
	l.Hostname = hostname.String
	l.SubnetID = subnet.String
	l.GIAddr = giaddr.String
	l.CircuitID = circuit.String
	l.RemoteID = remote.String
	l.LinkSelect = link.String
	if vlan.Valid {
		v := int(vlan.Int64)
		l.VLANID = &v
	}
	l.ExpiresAt = parseTime(exp.String)
	l.CreatedAt = parseTime(created.String)
	return l, nil
}

func scanLeases(rows *sql.Rows) ([]model.Lease, error) {
	var out []model.Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func scanSubnet(rows *sql.Rows) (model.Subnet, error) {
	var sub model.Subnet
	var vlan sql.NullInt64
	var dns, opts sql.NullString
	var rangeStart, rangeEnd, gateway, domain sql.NullString
	var lease sql.NullInt64
	if err := rows.Scan(&sub.ID, &sub.Network, &rangeStart, &rangeEnd, &gateway, &vlan, &domain, &dns, &opts, &lease); err != nil {
		return model.Subnet{}, err
	}
	sub.RangeStart = rangeStart.String
	sub.RangeEnd = rangeEnd.String
	sub.Gateway = gateway.String
	sub.Domain = domain.String
	sub.LeaseSec = int(lease.Int64)
	if vlan.Valid {
		v := int(vlan.Int64)
		sub.VLANID = &v
	}
	if dns.String != "" {
		_ = json.Unmarshal([]byte(dns.String), &sub.DNS)
	}
	if opts.String != "" {
		_ = json.Unmarshal([]byte(opts.String), &sub.Options)
	}
	return sub, nil
}

func scanRelay(rows *sql.Rows) (model.Relay, error) {
	var r model.Relay
	var remote, vendor, parser, subnet, created sql.NullString
	var trusted int
	var vlan sql.NullInt64
	if err := rows.Scan(&r.GIAddr, &remote, &vendor, &trusted, &parser, &vlan, &subnet, &created); err != nil {
		return model.Relay{}, err
	}
	r.RemoteID = remote.String
	r.Vendor = vendor.String
	r.ParserName = parser.String
	r.SubnetID = subnet.String
	r.Trusted = trusted != 0
	r.CreatedAt = parseTime(created.String)
	if vlan.Valid {
		v := int(vlan.Int64)
		r.VLANID = &v
	}
	return r, nil
}

func scanReservation(rows *sql.Rows) (model.Reservation, error) {
	var r model.Reservation
	var mac, client, host, subnet sql.NullString
	if err := rows.Scan(&r.ID, &mac, &client, &r.IP, &host, &subnet); err != nil {
		return model.Reservation{}, err
	}
	r.MAC = mac.String
	r.ClientID = client.String
	r.Hostname = host.String
	r.SubnetID = subnet.String
	return r, nil
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

// WithLeaseTransaction groups lease operations on this context into one commit.
// Other API requests retain their own contexts and cannot join the transaction.
func (s *SQLStore) WithLeaseTransaction(ctx context.Context, fn func(context.Context) error) error {
	if s.leaseTransaction(ctx) != nil {
		return fmt.Errorf("nested lease transaction is unsupported")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	batchCtx := context.WithValue(ctx, leaseTransactionKey{}, leaseTransactionContext{store: s, tx: tx})
	if err := fn(batchCtx); err != nil {
		return err
	}
	return commitLeaseTx(tx)
}

type leaseTransactionKey struct{}
type leaseTransactionContext struct {
	store *SQLStore
	tx    *sql.Tx
}

func (s *SQLStore) leaseTransaction(ctx context.Context) *sql.Tx {
	value, _ := ctx.Value(leaseTransactionKey{}).(leaseTransactionContext)
	if value.store == s {
		return value.tx
	}
	return nil
}
