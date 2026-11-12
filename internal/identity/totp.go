package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"time"
)

func codeAt(key []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(counter[:])
	sum := h.Sum(nil)
	pos := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[pos:pos+4])&0x7fffffff)%1000000)
}

func checkCode(key []byte, code string, now time.Time) (int64, bool) {
	if len(code) != 6 || len(key) != 20 {
		return 0, false
	}
	step := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		if subtle.ConstantTimeCompare([]byte(codeAt(key, step+offset)), []byte(code)) == 1 {
			return step + offset, true
		}
	}
	return 0, false
}

type Enrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func (s *Store) BeginTOTP(ctx context.Context, u User, password string) (Enrollment, error) {
	if !s.permit(u.Name) {
		return Enrollment{}, ErrBusy
	}
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	default:
		return Enrollment{}, ErrBusy
	}
	r, err := s.record(ctx, u.Name)
	if err != nil || r.Revision != u.Revision || r.Disabled || !s.password(ctx, r, password) {
		return Enrollment{}, ErrDenied
	}
	if r.TOTP {
		return Enrollment{}, errors.New("второй фактор уже настроен")
	}
	key := make([]byte, 20)
	if _, err = rand.Read(key); err != nil {
		return Enrollment{}, err
	}
	defer clear(key)
	encrypted, err := s.seal(u.Name, key)
	if err != nil {
		return Enrollment{}, err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE users SET pending=?,pending_until=? WHERE name=? AND revision=? AND totp IS NULL",
		encrypted, time.Now().Add(10*time.Minute).Unix(), u.Name, u.Revision)
	if err != nil {
		return Enrollment{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return Enrollment{}, ErrConflict
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "/GFW:" + u.Name, RawQuery: url.Values{"secret": {secret}, "issuer": {"GFW"}, "digits": {"6"}, "period": {"30"}}.Encode()}
	return Enrollment{Secret: secret, URI: uri.String()}, nil
}

func (s *Store) ConfirmTOTP(ctx context.Context, u User, code string) (User, error) {
	if !s.permit(u.Name) {
		return User{}, ErrBusy
	}
	r, err := s.record(ctx, u.Name)
	now := time.Now()
	if err != nil || r.Disabled || r.Revision != u.Revision || r.TOTP || now.Unix() >= r.until {
		return User{}, ErrDenied
	}
	key, err := s.unseal(u.Name, r.pending)
	if err != nil {
		return User{}, ErrDenied
	}
	defer clear(key)
	step, ok := checkCode(key, code, now)
	if !ok {
		return User{}, ErrDenied
	}
	result, err := s.db.ExecContext(ctx, "UPDATE users SET totp=pending,pending=NULL,pending_until=0,last_step=?,revision=revision+1 WHERE name=? AND revision=? AND pending=? AND disabled=0",
		step, u.Name, u.Revision, r.pending)
	if err != nil {
		return User{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return User{}, ErrConflict
	}
	return s.User(ctx, u.Name)
}
