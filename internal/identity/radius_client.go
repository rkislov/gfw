package identity

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"time"
)

type RadiusConfig struct {
	Address string `json:"address"`
	Secret  string `json:"secret,omitempty"`
}

func (s *Store) Radius() (RadiusConfig, error) {
	var c RadiusConfig
	err := s.vault.Get("radius", &c)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return c, err
}

func (s *Store) SaveRadius(c RadiusConfig) error {
	old, err := s.Radius()
	if err != nil {
		return err
	}
	if c.Address == "" {
		if c.Secret != "" {
			return errors.New("укажите адрес RADIUS")
		}
		return s.vault.Put("radius", c)
	}
	if c.Address == old.Address && c.Secret == "" {
		c.Secret = old.Secret
	}
	host, port, err := net.SplitHostPort(c.Address)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host == "" || len(host) > 253 || n < 1 || n > 65535 || len(c.Secret) < 16 || len(c.Secret) > 256 {
		return errors.New("укажите сервер RADIUS в формате адрес:порт и секрет от 16 до 256 байт")
	}
	return s.vault.Put("radius", c)
}

func (c RadiusConfig) bind(ctx context.Context, name, password string) error {
	if c.Address == "" || len(password) < 1 || len(password) > 128 {
		return ErrDenied
	}
	key := []byte(c.Secret)
	req := make([]byte, 20)
	if _, err := rand.Read(req[1:20]); err != nil {
		return err
	}
	req[0] = 1
	appendAttr := func(kind byte, v []byte) { req = append(req, kind, byte(len(v)+2)); req = append(req, v...) }
	appendAttr(1, []byte(name))
	padded := make([]byte, (len(password)+15)/16*16)
	copy(padded, password)
	previous := req[4:20]
	for i := 0; i < len(padded); i += 16 {
		digest := md5.New()
		digest.Write(key)
		digest.Write(previous)
		mask := digest.Sum(nil)
		for j := range 16 {
			padded[i+j] ^= mask[j]
		}
		previous = padded[i : i+16]
	}
	appendAttr(2, padded)
	clear(padded)
	appendAttr(32, []byte("gfw"))
	appendAttr(80, make([]byte, 16))
	binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
	mac := hmac.New(md5.New, key)
	mac.Write(req)
	copy(req[len(req)-16:], mac.Sum(nil))
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", c.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = conn.Write(req); err != nil {
		return err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil || n < 20 {
		return ErrDenied
	}
	return verifyRadiusAccept(req, response[:n], key)
}

func verifyRadiusAccept(req, resp, key []byte) error {
	if len(resp) < 20 || resp[0] != 2 || resp[1] != req[1] || int(binary.BigEndian.Uint16(resp[2:4])) != len(resp) {
		return ErrDenied
	}
	authenticator := append([]byte(nil), resp[4:20]...)
	copy(resp[4:20], req[4:20])
	digest := md5.New()
	digest.Write(resp)
	digest.Write(key)
	if !hmac.Equal(authenticator, digest.Sum(nil)) {
		return ErrDenied
	}
	pos := 0
	for i := 20; i < len(resp); {
		if len(resp)-i < 2 {
			return ErrDenied
		}
		size := int(resp[i+1])
		if size < 2 || size > len(resp)-i {
			return ErrDenied
		}
		if resp[i] == 80 {
			if pos != 0 || size != 18 {
				return ErrDenied
			}
			pos = i + 2
		}
		i += size
	}
	if pos == 0 {
		return ErrDenied
	}
	saved := append([]byte(nil), resp[pos:pos+16]...)
	clear(resp[pos : pos+16])
	mac := hmac.New(md5.New, key)
	mac.Write(resp)
	if !hmac.Equal(saved, mac.Sum(nil)) {
		return ErrDenied
	}
	return nil
}
