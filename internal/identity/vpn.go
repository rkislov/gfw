package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const DefaultSocket = "/run/gfw-auth/openvpn.sock"
const DefaultKey = "/etc/gfw/vpn-auth.key"
const RadiusAddress = "127.0.0.1:18128"

type VPNRequest struct {
	Grant      string `json:"grant"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	CommonName string `json:"common_name"`
	Method     Method `json:"method"`
}

func ReadKey(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", errors.New("неверный ключ брокера VPN")
	}
	clear(key)
	return value, nil
}

func (s *Store) verifyVPN(ctx context.Context, in VPNRequest, certBound bool) bool {
	if !Grant.MatchString(in.Grant) || in.Method.Validate() != nil || !in.Method.Credentials() {
		return false
	}
	if in.Method.Certificate && !certBound && in.Username != in.CommonName {
		return false
	}
	password, code := SplitCode(in.Secret, in.Method.TOTP)
	if in.Method.TOTP && in.Method.Password == "" {
		password, code = "", in.Secret
	}
	_, err := s.Authenticate(ctx, in.Username, password, code, in.Method, in.Grant, false)
	return err == nil
}

// OpenVPN reaches the controller only through a private authenticated Unix socket.
func (s *Store) ListenVPN(path, key string) (*http.Server, net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, errors.New("путь брокера VPN занят")
		}
		if c, e := net.DialTimeout("unix", path, time.Second); e == nil {
			c.Close()
			return nil, nil, errors.New("брокер VPN уже запущен")
		}
		if err = os.Remove(path); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(path, 0660); err != nil {
		listener.Close()
		return nil, nil, err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/openvpn" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+key)) != 1 {
			w.WriteHeader(403)
			return
		}
		var in VPNRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		if dec.Decode(&in) != nil || !strings.HasPrefix(in.Grant, "openvpn:") || !s.verifyVPN(r.Context(), in, false) {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	})
	return &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 7 * time.Second, IdleTimeout: 5 * time.Second}, listener, nil
}

// RunOpenVPNHook reads the file supplied by OpenVPN. Neither passwords nor
// codes are passed via command-line arguments, environment, or logs.
func RunOpenVPNHook(args []string) error {
	if len(args) != 5 {
		return ErrDenied
	}
	mode, err := parseMethod(args[1], args[2], args[3])
	if err != nil {
		return ErrDenied
	}
	file, err := os.Open(args[4])
	if err != nil {
		return ErrDenied
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil || len(raw) > 2048 {
		return ErrDenied
	}
	user, secret, ok := strings.Cut(strings.TrimSuffix(string(raw), "\n"), "\n")
	clear(raw)
	if !ok || strings.ContainsAny(secret, "\r\n\x00") {
		return ErrDenied
	}
	socket := os.Getenv("GFW_VPN_AUTH_SOCKET")
	if socket == "" {
		socket = DefaultSocket
	}
	keyPath := os.Getenv("GFW_VPN_AUTH_KEY")
	if keyPath == "" {
		keyPath = DefaultKey
	}
	key, err := ReadKey(keyPath)
	if err != nil {
		return ErrDenied
	}
	data, err := json.Marshal(VPNRequest{Grant: "openvpn:" + args[0], Username: user, Secret: secret, CommonName: os.Getenv("common_name"), Method: mode})
	if err != nil {
		return ErrDenied
	}
	defer clear(data)
	client := http.Client{Timeout: 7 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}
	req, err := http.NewRequest("POST", "http://broker/openvpn", bytes.NewReader(data))
	if err != nil {
		return ErrDenied
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		return ErrDenied
	}
	return nil
}

func parseMethod(source, cert, totp string) (Method, error) {
	if source == "none" {
		source = ""
	}
	if (cert != "true" && cert != "false") || (totp != "true" && totp != "false") {
		return Method{}, ErrDenied
	}
	m := Method{Password: source, Certificate: cert == "true", TOTP: totp == "true"}
	return m, m.Validate()
}

func (m Method) Arguments() string {
	source := m.Password
	if source == "" {
		source = "none"
	}
	cert, totp := "false", "false"
	if m.Certificate {
		cert = "true"
	}
	if m.TOTP {
		totp = "true"
	}
	return strings.Join([]string{source, cert, totp}, " ")
}
