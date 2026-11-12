package identity

import (
	"context"
	"encoding/base32"
	"errors"
	"net"
	"testing"
	"time"
)

func TestVPNRequiresGrantAndRejectsReusedTOTP(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const password = "a:local password"
	u, err := s.Save(ctx, User{Name: "alice", Source: "local", Role: "user", Grants: []string{"openvpn:office"}}, password, false)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := s.BeginTOTP(ctx, u, password)
	if err != nil {
		t.Fatal(err)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	step := time.Now().Unix() / 30
	// Enroll using the current code and exercise the permitted next window.
	u, err = s.ConfirmTOTP(ctx, u, codeAt(key, step))
	if err != nil || !u.TOTP {
		t.Fatal(u, err)
	}
	code := codeAt(key, step+1)
	req := VPNRequest{Grant: "openvpn:office", Username: "alice", CommonName: "bob", Secret: password + ":" + code,
		Method: Method{Password: "local", Certificate: true, TOTP: true}}
	if s.verifyVPN(ctx, req, false) {
		t.Fatal("accepted a different certificate identity")
	}
	req.CommonName, req.Grant = "alice", "openvpn:other"
	if s.verifyVPN(ctx, req, false) {
		t.Fatal("accepted a missing VPN assignment")
	}
	req.Grant = "openvpn:office"
	if !s.verifyVPN(ctx, req, false) {
		t.Fatal("valid VPN authentication rejected")
	}
	if _, err := s.Authenticate(ctx, "alice", password, code, Method{}, "", true); !errors.Is(err, ErrDenied) {
		t.Fatalf("VPN code reused for panel login: %v", err)
	}
}

func TestExternalRadiusRequiresAuthenticatedResponse(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const secret = "test-shared-key-long"
	const password = "a password larger than 16 bytes"
	result := make(chan error, 1)
	go func() {
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		for i := 0; i < 2; i++ {
			raw := make([]byte, 4096)
			n, from, err := conn.ReadFromUDP(raw)
			if err != nil {
				result <- err
				return
			}
			request := raw[:n]
			user, pass, nas, ok := parseRadius(request, []byte(secret))
			if !ok || user != "alice" || pass != password || nas != "gfw" {
				result <- errors.New("unexpected Access-Request")
				return
			}
			reply := radiusReply(request, []byte(secret), 2)
			if i == 1 {
				reply[23] ^= 1
			}
			if _, err = conn.WriteToUDP(reply, from); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	config := RadiusConfig{Address: conn.LocalAddr().String(), Secret: secret}
	if err = config.bind(context.Background(), "alice", password); err != nil {
		t.Fatal(err)
	}
	if err = config.bind(context.Background(), "alice", password); !errors.Is(err, ErrDenied) {
		t.Fatalf("tampered Access-Accept: %v", err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}

func TestDefaultAdminOnlyInitializesNewStores(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.Authenticate(ctx, "admin", "admin", "", Method{}, "", true)
	if err != nil || !admin.DefaultPassword || admin.Role != "admin" {
		t.Fatalf("unexpected bootstrap result: %+v (%v)", admin, err)
	}
	const replacement = "changed password 2026"
	updated, err := s.Save(ctx, admin, replacement, false)
	if err != nil || updated.DefaultPassword {
		t.Fatalf("default flag survived password change: %+v (%v)", updated, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Authenticate(ctx, "admin", "admin", "", Method{}, "", true); !errors.Is(err, ErrDenied) {
		t.Fatalf("default password was accepted after restart: %v", err)
	}
	if u, e := s.Authenticate(ctx, "admin", replacement, "", Method{}, "", true); e != nil || u.DefaultPassword {
		t.Fatalf("replacement password not preserved: %+v (%v)", u, e)
	}

	// Model a prior installation with the existing users table and no bootstrap metadata.
	if _, err = s.db.Exec("DELETE FROM users WHERE name='admin'; DROP TABLE default_credentials;"); err != nil {
		t.Fatal(err)
	}
	legacy, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, err = legacy.Authenticate(ctx, "admin", "admin", "", Method{}, "", true); !errors.Is(err, ErrDenied) {
		t.Fatalf("upgrade initialized a default administrator: %v", err)
	}
}
