package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/vpncred"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var ErrDenied = errors.New("неверные данные входа")
var ErrConflict = errors.New("учётная запись изменилась")
var ErrBusy = errors.New("слишком много попыток входа")

type Store struct {
	db       *sql.DB
	aead     cipher.AEAD
	vault    *vpncred.Vault
	work     chan struct{}
	mu       sync.Mutex
	attempts map[string]bucket
}

type bucket struct {
	until time.Time
	count int
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	vault, err := vpncred.OpenVault(filepath.Join(dir, "secrets"))
	if err != nil {
		return nil, err
	}
	var key []byte
	if err = vault.Get("identity-key", &key); errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		err = vault.Put("identity-key", key)
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "identity.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, source TEXT NOT NULL, role TEXT NOT NULL,
 disabled INTEGER NOT NULL, password BLOB, totp BLOB, pending BLOB, pending_until INTEGER NOT NULL DEFAULT 0,
 last_step INTEGER NOT NULL DEFAULT -1, grants TEXT NOT NULL, revision INTEGER NOT NULL);
`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, aead: aead, vault: vault, work: make(chan struct{}, 4), attempts: map[string]bucket{}}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const selectUser = `SELECT name,source,role,disabled,password,totp,pending,pending_until,last_step,grants,revision FROM users`

type record struct {
	User
	password, totp, pending []byte
	until, last             int64
}
type scanner interface{ Scan(...any) error }

func scan(row scanner) (record, error) {
	var r record
	var grants string
	err := row.Scan(&r.Name, &r.Source, &r.Role, &r.Disabled, &r.password, &r.totp, &r.pending, &r.until, &r.last, &grants, &r.Revision)
	if err != nil {
		return r, err
	}
	r.TOTP = len(r.totp) > 0
	err = json.Unmarshal([]byte(grants), &r.Grants)
	return r, err
}

func (s *Store) record(ctx context.Context, name string) (record, error) {
	return scan(s.db.QueryRowContext(ctx, selectUser+" WHERE name=?", name))
}
func (s *Store) User(ctx context.Context, name string) (User, error) {
	r, err := s.record(ctx, name)
	return r.User, err
}
func (s *Store) List(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, selectUser+" ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		r, e := scan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r.User)
	}
	return out, rows.Err()
}

func (s *Store) Save(ctx context.Context, u User, password string, resetTOTP bool) (User, error) {
	if err := u.Validate(); err != nil {
		return User{}, err
	}
	if u.Revision < 0 || u.Source != "local" && password != "" {
		return User{}, errors.New("некорректные параметры пароля или ревизии")
	}
	var hash []byte
	if password != "" {
		if len(password) < 12 || len(password) > 72 || strings.ContainsAny(password, "\x00\r\n") {
			return User{}, errors.New("локальный пароль должен содержать 12–72 байта без управляющих переводов строки")
		}
		var err error
		hash, err = bcrypt.GenerateFromPassword([]byte(password), 11)
		if err != nil {
			return User{}, err
		}
	}
	grants := append([]string{}, u.Grants...)
	slices.Sort(grants)
	raw, err := json.Marshal(slices.Compact(grants))
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	old, err := scan(tx.QueryRowContext(ctx, selectUser+" WHERE name=?", u.Name))
	if errors.Is(err, sql.ErrNoRows) {
		if u.Revision != 0 {
			return User{}, ErrConflict
		}
		if u.Source == "local" && hash == nil {
			return User{}, errors.New("задайте пароль для новой локальной учётной записи")
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
			return User{}, err
		}
		if count >= 2048 {
			return User{}, errors.New("достигнут лимит 2048 пользователей")
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO users(name,source,role,disabled,password,grants,revision) VALUES(?,?,?,?,?,?,1)", u.Name, u.Source, u.Role, u.Disabled, hash, string(raw))
	} else if err == nil {
		if u.Revision != old.Revision || u.Source != old.Source {
			return User{}, ErrConflict
		}
		if hash == nil {
			hash = old.password
		}
		if resetTOTP {
			old.totp = nil
			old.last = -1
		}
		_, err = tx.ExecContext(ctx, "UPDATE users SET role=?,disabled=?,password=?,totp=?,last_step=?,pending=NULL,pending_until=0,grants=?,revision=revision+1 WHERE name=?", u.Role, u.Disabled, hash, old.totp, old.last, string(raw), u.Name)
	}
	if err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	return s.User(ctx, u.Name)
}

func (s *Store) permit(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	b := s.attempts[name]
	if !now.Before(b.until) {
		if len(s.attempts) >= 4096 {
			for k, v := range s.attempts {
				if !now.Before(v.until) {
					delete(s.attempts, k)
				}
			}
			if len(s.attempts) >= 4096 {
				return false
			}
		}
		b = bucket{until: now.Add(time.Minute)}
	}
	b.count++
	s.attempts[name] = b
	return b.count <= 12
}

func (s *Store) Authenticate(ctx context.Context, name, password, code string, method Method, grant string, web bool) (User, error) {
	if !Username.MatchString(name) || len(password) > 1024 || len(code) > 16 {
		return User{}, ErrDenied
	}
	if !s.permit(name) {
		return User{}, ErrBusy
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		return User{}, ErrBusy
	}
	r, err := s.record(ctx, name)
	if err != nil || r.Disabled || grant != "" && !r.HasGrant(grant) {
		return User{}, ErrDenied
	}
	if web {
		method.Password = r.Source
		method.TOTP = r.TOTP
	}
	if method.Password != "" && ((method.Password != "either" && method.Password != r.Source || method.Password == "either" && r.Source == "radius") || !s.password(ctx, r, password)) {
		return User{}, ErrDenied
	}
	if method.TOTP {
		key, err := s.unseal(r.Name, r.totp)
		if err != nil {
			return User{}, ErrDenied
		}
		step, ok := checkCode(key, code, time.Now())
		clear(key)
		if !ok {
			return User{}, ErrDenied
		}
		result, err := s.db.ExecContext(ctx, "UPDATE users SET last_step=? WHERE name=? AND revision=? AND last_step<? AND disabled=0", step, r.Name, r.Revision, step)
		if err != nil {
			return User{}, err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return User{}, ErrDenied
		}
	}
	current, err := s.User(ctx, name)
	if err != nil || current.Revision != r.Revision || current.Disabled {
		return User{}, ErrDenied
	}
	return current, nil
}

func (s *Store) password(ctx context.Context, r record, password string) bool {
	if password == "" || strings.ContainsAny(password, "\x00\r\n") {
		return false
	}
	if r.Source == "local" {
		return len(password) <= 72 && bcrypt.CompareHashAndPassword(r.password, []byte(password)) == nil
	}
	if r.Source == "radius" {
		config, err := s.Radius()
		return err == nil && config.bind(ctx, r.Name, password) == nil
	}
	config, err := s.LDAP()
	return err == nil && config.bind(ctx, r.Name, password) == nil
}

func (s *Store) seal(name string, secret []byte) ([]byte, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return s.aead.Seal(n, n, secret, []byte(name)), nil
}
func (s *Store) unseal(name string, secret []byte) ([]byte, error) {
	size := s.aead.NonceSize()
	if len(secret) <= size {
		return nil, fmt.Errorf("TOTP недоступен")
	}
	return s.aead.Open(nil, secret[:size], secret[size:], []byte(name))
}
