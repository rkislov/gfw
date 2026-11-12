// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"
)

// IPv6 leases are separate from the IPv4 catalog and DDNS reconciliation.
type IPv6Store interface {
	InitIPv6(context.Context, []byte) ([]byte, error)
	ApplyIPv6(context.Context, IPv6Request) (netip.Addr, error)
}

type IPv6Action int

const (
	Advertise6 IPv6Action = iota
	Bind6
	Renew6
	Release6
	Decline6
)

type IPv6Request struct {
	Action         IPv6Action
	Prefix, Client string
	IAID           uint32
	Start, End     netip.Addr
	Hints          []netip.Addr
	Now            time.Time
	Lifetime       time.Duration
}

var ErrNoBinding6 = errors.New("no IPv6 binding")
var ErrNoAddress6 = errors.New("IPv6 pool exhausted")

func (s *SQLStore) InitIPv6(ctx context.Context, configured []byte) ([]byte, error) {
	for _, q := range []string{
		"CREATE TABLE IF NOT EXISTS dhcp6_identity (id INTEGER PRIMARY KEY, duid TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS dhcp6_leases (ip TEXT PRIMARY KEY, prefix TEXT NOT NULL, client TEXT, iaid BIGINT NOT NULL, state TEXT NOT NULL, expires BIGINT NOT NULL, UNIQUE(prefix,client,iaid))",
		"CREATE INDEX IF NOT EXISTS dhcp6_expiry ON dhcp6_leases(expires)",
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return nil, err
		}
	}
	if len(configured) > 0 {
		return configured, nil
	}
	id := make([]byte, 18)
	id[1] = 4 // DUID-UUID
	if _, err := rand.Read(id[2:]); err != nil {
		return nil, err
	}
	id[8] = id[8]&15 | 64
	id[10] = id[10]&63 | 128
	if _, err := s.db.ExecContext(ctx, s.q("INSERT INTO dhcp6_identity(id,duid) VALUES(1,?) ON CONFLICT(id) DO NOTHING"), hex.EncodeToString(id)); err != nil {
		return nil, err
	}
	var saved string
	if err := s.db.QueryRowContext(ctx, "SELECT duid FROM dhcp6_identity WHERE id=1").Scan(&saved); err != nil {
		return nil, err
	}
	return hex.DecodeString(saved)
}

func (s *SQLStore) ApplyIPv6(ctx context.Context, r IPv6Request) (netip.Addr, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer tx.Rollback()
	// Serialize allocation across processes. SQLite takes the writer lock on DELETE.
	if s.postgres {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(6743546)"); err != nil {
			return netip.Addr{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, s.q("DELETE FROM dhcp6_leases WHERE expires<=?"), r.Now.Unix()); err != nil {
		return netip.Addr{}, err
	}
	ip, err := s.applyIPv6(ctx, tx, r)
	if err != nil && !errors.Is(err, ErrNoBinding6) && !errors.Is(err, ErrNoAddress6) {
		return netip.Addr{}, err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return netip.Addr{}, commitErr
	}
	return ip, err
}

func (s *SQLStore) applyIPv6(ctx context.Context, tx *sql.Tx, r IPv6Request) (netip.Addr, error) {
	var saved, state string
	err := tx.QueryRowContext(ctx, s.q("SELECT ip,state FROM dhcp6_leases WHERE prefix=? AND client=? AND iaid=?"), r.Prefix, r.Client, r.IAID).Scan(&saved, &state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, err
	}
	ip, _ := netip.ParseAddr(saved)
	expiry := r.Now.Add(r.Lifetime).Unix()
	switch r.Action {
	case Renew6, Release6, Decline6:
		matches := len(r.Hints) == 0 && r.Action == Renew6
		for _, hint := range r.Hints {
			if ip == hint {
				matches = true
			}
		}
		if state != "bound" || !matches || (r.Action == Renew6 && (ip.Compare(r.Start) < 0 || ip.Compare(r.End) > 0)) {
			return netip.Addr{}, ErrNoBinding6
		}
		switch r.Action {
		case Release6:
			_, err = tx.ExecContext(ctx, s.q("DELETE FROM dhcp6_leases WHERE ip=?"), saved)
		case Decline6:
			_, err = tx.ExecContext(ctx, s.q("UPDATE dhcp6_leases SET client=NULL,state='declined',expires=? WHERE ip=?"), expiry, saved)
		case Renew6:
			_, err = tx.ExecContext(ctx, s.q("UPDATE dhcp6_leases SET expires=? WHERE ip=?"), expiry, saved)
		}
		return ip, err
	}
	if ip.IsValid() {
		if ip.Compare(r.Start) < 0 || ip.Compare(r.End) > 0 {
			return netip.Addr{}, ErrNoAddress6
		}
		if r.Action == Advertise6 && state == "bound" {
			return ip, nil
		}
	} else {
		ip, err = s.availableIPv6(ctx, tx, r)
		if err != nil {
			return netip.Addr{}, err
		}
	}
	state = "offered"
	if r.Action == Bind6 {
		state = "bound"
	}
	_, err = tx.ExecContext(ctx, s.q("INSERT INTO dhcp6_leases(ip,prefix,client,iaid,state,expires) VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET state=excluded.state,expires=excluded.expires"), ip.String(), r.Prefix, r.Client, r.IAID, state, expiry)
	return ip, err
}

func (s *SQLStore) availableIPv6(ctx context.Context, tx *sql.Tx, r IPv6Request) (netip.Addr, error) {
	rows, err := tx.QueryContext(ctx, "SELECT ip FROM dhcp6_leases")
	if err != nil {
		return netip.Addr{}, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return netip.Addr{}, err
		}
		used[ip] = true
	}
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range r.Hints {
		if ip.Compare(r.Start) >= 0 && ip.Compare(r.End) <= 0 && !used[ip.String()] {
			return ip, nil
		}
	}
	for ip := r.Start; ip.IsValid() && ip.Compare(r.End) <= 0; ip = ip.Next() {
		if !used[ip.String()] {
			return ip, nil
		}
	}
	return netip.Addr{}, ErrNoAddress6
}
