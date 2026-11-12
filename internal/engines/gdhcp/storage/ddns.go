// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// DNSRecord is both a durable update intent and the last successful application.
// It is saved BEFORE contacting DNS, so crash recovery retains ownership tokens.
type DNSRecord struct {
	Server       string    `json:"server"`
	Zone         string    `json:"zone"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Value        string    `json:"value"`
	Token        string    `json:"token"`
	TTL          uint32    `json:"ttl"`
	LeaseExpires time.Time `json:"lease_expires"`
	AppliedAt    time.Time `json:"applied_at"`
}

func (r DNSRecord) Key() string { return r.Server + "|" + r.Zone + "|" + r.Name + "|" + r.Type }

type DNSStore interface {
	InitDNS(context.Context) (string, error)
	DNSRecords(context.Context) ([]DNSRecord, error)
	PutDNSRecord(context.Context, DNSRecord) error
	DeleteDNSRecord(context.Context, string) error
}

func (s *SQLStore) InitDNS(ctx context.Context) (string, error) {
	for _, q := range []string{`CREATE TABLE IF NOT EXISTS ddns_identity (id INTEGER PRIMARY KEY, owner TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS ddns_records (record_key TEXT PRIMARY KEY, data TEXT NOT NULL)`} {
		if _, e := s.db.ExecContext(ctx, q); e != nil {
			return "", e
		}
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	if _, e := s.db.ExecContext(ctx, s.q(`INSERT INTO ddns_identity(id,owner) VALUES (1,?) ON CONFLICT(id) DO NOTHING`), hex.EncodeToString(raw)); e != nil {
		return "", e
	}
	var owner string
	e := s.db.QueryRowContext(ctx, `SELECT owner FROM ddns_identity WHERE id=1`).Scan(&owner)
	return owner, e
}
func (s *SQLStore) DNSRecords(ctx context.Context) ([]DNSRecord, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT data FROM ddns_records ORDER BY record_key`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := make([]DNSRecord, 0)
	for rows.Next() {
		var raw string
		if e := rows.Scan(&raw); e != nil {
			return nil, e
		}
		var r DNSRecord
		if e := json.Unmarshal([]byte(raw), &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *SQLStore) PutDNSRecord(ctx context.Context, r DNSRecord) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, s.q(`INSERT INTO ddns_records(record_key,data) VALUES (?,?) ON CONFLICT(record_key) DO UPDATE SET data=excluded.data`), r.Key(), string(b))
	return e
}
func (s *SQLStore) DeleteDNSRecord(ctx context.Context, key string) error {
	_, e := s.db.ExecContext(ctx, s.q(`DELETE FROM ddns_records WHERE record_key=?`), key)
	return e
}
