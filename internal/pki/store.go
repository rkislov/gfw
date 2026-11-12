// Package pki owns certificate keys, local issuing CAs, ACME and panel TLS.
package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Certificate struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	CAID        string     `json:"ca_id"`
	ProfileID   string     `json:"profile_id"`
	Usage       string     `json:"usage"`
	DNSNames    []string   `json:"dns_names"`
	IPs         []string   `json:"ips"`
	Serial      string     `json:"serial"`
	Fingerprint string     `json:"fingerprint"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
type entry struct {
	Certificate
	PEM       []byte
	Key       []byte
	CRL       []byte
	CRLNumber int64
}
type Manager struct {
	lock             *os.File
	db               *sql.DB
	aead             cipher.AEAD
	mu               sync.Mutex
	tls              tlsState
	challengeEnabled bool
	wake             chan struct{}
	now              func() time.Time
	HTTPClient       HTTPDoer
}

func privateFile(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s must be a private regular file", filepath.Base(path))
	}
	return os.ReadFile(path)
}
func Open(root string) (*Manager, error) {
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(root)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("PKI directory must be private (0700), not a symlink")
	}
	lock, e := os.OpenFile(filepath.Join(root, "vault.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("another controller owns this PKI vault")
	}
	opened := false
	defer func() {
		if !opened {
			lock.Close()
		}
	}()
	masterPath := filepath.Join(root, "device.key")
	master, e := privateFile(masterPath)
	if errors.Is(e, os.ErrNotExist) {
		// Never generate a replacement key for an existing vault.
		if _, err := os.Lstat(filepath.Join(root, "pki.db")); err == nil {
			return nil, errors.New("device key missing for existing PKI database; restore the backup")
		}
		master = make([]byte, 32)
		if _, e = rand.Read(master); e != nil {
			return nil, e
		}
		f, err := os.OpenFile(masterPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, e = f.Write(master)
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if len(master) != 32 {
		return nil, errors.New("invalid device key")
	}
	// Make the device-key directory entry durable before creating a vault
	// whose encrypted records depend on that key.
	directory, e := os.Open(root)
	if e != nil {
		return nil, e
	}
	e = errors.Join(directory.Sync(), directory.Close())
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(master)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(root, "pki.db")
	if _, e = os.Lstat(path); e == nil {
		if info, e := os.Lstat(path); e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("PKI database must be a private regular file")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	m := &Manager{lock: lock, db: db, aead: aead, wake: make(chan struct{}, 1), now: time.Now}
	fail := func(e error) (*Manager, error) { db.Close(); return nil, e }
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS vault_version(version INTEGER NOT NULL);
 INSERT INTO vault_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM vault_version);
 CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,meta TEXT NOT NULL,pem BLOB NOT NULL,secret BLOB NOT NULL,crl BLOB,crl_number INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS vault_audit(id INTEGER PRIMARY KEY,at TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS panel_tls(id INTEGER PRIMARY KEY CHECK(id=1),active_id TEXT NOT NULL DEFAULT '',pending_id TEXT NOT NULL DEFAULT '',deadline TEXT NOT NULL DEFAULT '',hostname TEXT NOT NULL DEFAULT '');
 INSERT OR IGNORE INTO panel_tls(id) VALUES(1);
 CREATE TABLE IF NOT EXISTS acme_profiles(id TEXT PRIMARY KEY,body TEXT NOT NULL,secret BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS acme_jobs(id TEXT PRIMARY KEY,profile_id TEXT NOT NULL,body TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS acme_challenges(token TEXT PRIMARY KEY,hostname TEXT NOT NULL,response TEXT NOT NULL,expires TEXT NOT NULL);`)
	if e != nil {
		return fail(e)
	}
	var version int
	if e = db.QueryRow("SELECT version FROM vault_version").Scan(&version); e != nil || version != 1 {
		return fail(errors.New("unsupported PKI database version"))
	}
	if _, e = db.Exec("DELETE FROM acme_challenges"); e != nil {
		return fail(e)
	}
	// Detect a replaced device key before exposing or changing any objects.
	var secret []byte
	e = db.QueryRow("SELECT secret FROM certificates UNION ALL SELECT secret FROM acme_profiles LIMIT 1").Scan(&secret)
	if e != sql.ErrNoRows {
		if e != nil {
			return fail(e)
		}
		if _, e = m.decrypt(secret); e != nil {
			return fail(e)
		}
	}
	opened = true
	return m, nil
}
func (m *Manager) Close() error { return errors.Join(m.db.Close(), m.lock.Close()) }
func id() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func (m *Manager) encrypt(raw []byte) ([]byte, error) {
	n := make([]byte, m.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return m.aead.Seal(n, n, raw, []byte("gfw-pki-v1")), nil
}
func (m *Manager) decrypt(raw []byte) ([]byte, error) {
	n := m.aead.NonceSize()
	if len(raw) < n {
		return nil, errors.New("invalid encrypted private key")
	}
	out, e := m.aead.Open(nil, raw[:n], raw[n:], []byte("gfw-pki-v1"))
	if e != nil {
		return nil, errors.New("private key cannot be decrypted; check device key and backup")
	}
	return out, nil
}
func audit(tx *sql.Tx, action, obj string, now time.Time) error {
	_, e := tx.Exec("INSERT INTO vault_audit(at,action,object_id) VALUES(?,?,?)", now.UTC().Format(time.RFC3339Nano), action, obj)
	return e
}
func (m *Manager) get(id string) (entry, error) {
	var x entry
	var meta string
	var secret []byte
	e := m.db.QueryRow("SELECT meta,pem,secret,crl,crl_number FROM certificates WHERE id=?", id).Scan(&meta, &x.PEM, &secret, &x.CRL, &x.CRLNumber)
	if e != nil {
		return x, e
	}
	if e = json.Unmarshal([]byte(meta), &x.Certificate); e != nil {
		return x, e
	}
	x.Key, e = m.decrypt(secret)
	return x, e
}
func (m *Manager) List() ([]Certificate, error) {
	rows, e := m.db.Query("SELECT meta FROM certificates ORDER BY rowid DESC LIMIT 1000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var body string
		if e = rows.Scan(&body); e != nil {
			return nil, e
		}
		var c Certificate
		if e = json.Unmarshal([]byte(body), &c); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (m *Manager) insert(tx *sql.Tx, e entry) error {
	meta, err := json.Marshal(e.Certificate)
	if err != nil {
		return err
	}
	secret, err := m.encrypt(e.Key)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO certificates(id,meta,pem,secret,crl,crl_number) VALUES(?,?,?,?,?,?)", e.ID, string(meta), e.PEM, secret, e.CRL, e.CRLNumber)
	return err
}
func (m *Manager) PublicPEM(id string) ([]byte, error) {
	var raw []byte
	e := m.db.QueryRow("SELECT pem FROM certificates WHERE id=?", id).Scan(&raw)
	return raw, e
}
func fingerprint(der []byte) string { sum := sha256.Sum256(der); return hex.EncodeToString(sum[:]) }
func (m *Manager) Audit() ([]map[string]any, error) {
	rows, e := m.db.Query("SELECT at,action,object_id FROM vault_audit ORDER BY id DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, action, obj string
		if e = rows.Scan(&at, &action, &obj); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"at": at, "action": action, "object_id": obj})
	}
	return out, rows.Err()
}
