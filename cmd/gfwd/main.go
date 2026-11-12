package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/rkislov/gfw/internal/identity"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkislov/gfw/internal/pki"
	"github.com/rkislov/gfw/internal/server"
	"github.com/rkislov/gfw/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("gfwd stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", "127.0.0.1:8088", "HTTP(S) listen address")
	data := flag.String("data-dir", "./data", "private state directory")
	agent := flag.String("agent-socket", "", "optional gfw-agent Unix socket; otherwise inventory is local")
	cert := flag.String("tls-cert", "", "TLS certificate path")
	key := flag.String("tls-key", "", "TLS private key path")
	acmeListen := flag.String("acme-listen", "", "optional HTTP-01 challenge listener; public validation needs TCP/80")
	vpnSocket := flag.String("vpn-auth-socket", "", "private OpenVPN authentication socket")
	vpnKey := flag.String("vpn-auth-key", "", "local VPN authentication shared key file")
	flag.Parse()
	if (*cert == "") != (*key == "") {
		return errors.New("tls-cert and tls-key must be specified together")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if *cert == "" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("non-loopback listener requires TLS; use an SSH tunnel for local HTTP")
	}
	if err = os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	info, err := os.Stat(*data)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("data directory must have mode 0700")
	}
	token, err := loadToken(filepath.Join(*data, "admin.token"))
	if err != nil {
		return err
	}
	dbPath := filepath.Join(*data, "gfw.db")
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = os.Chmod(dbPath, 0600); err != nil {
		return err
	}
	vault, err := pki.Open(filepath.Join(*data, "pki"))
	if err != nil {
		return err
	}
	defer vault.Close()
	api := server.New(db, token, *agent)
	api.PKI = vault
	if err = api.EnableIdentity(filepath.Join(*data, "identity")); err != nil {
		return err
	}
	defer api.CloseIdentity()
	if *vpnSocket != "" {
		key, err := identity.ReadKey(*vpnKey)
		if err != nil {
			return err
		}
		broker, listener, radius, err := api.VPNBroker(*vpnSocket, key)
		if err != nil {
			return err
		}
		defer broker.Close()
		defer listener.Close()
		defer radius.Close()
	}

	if err := api.EnableFeed(filepath.Join(*data, "feed")); err != nil {
		slog.Error("Security Feed disabled", "error", err)
	}
	srv := &http.Server{Addr: *listen, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 95 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if *cert != "" {
		fallback, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return e
		}
		h, p, e := net.SplitHostPort(listener.Addr().String())
		if e != nil {
			return e
		}
		if h == "" || h == "0.0.0.0" {
			h = "127.0.0.1"
		}
		if h == "::" {
			h = "::1"
		}
		if e = vault.AttachTLS(fallback, pki.Probe(net.JoinHostPort(h, p))); e != nil {
			return e
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: vault.GetCertificate}
	}
	var challengeServer *http.Server
	var challengeListener net.Listener
	if *acmeListen != "" {
		challengeListener, err = net.Listen("tcp", *acmeListen)
		if err != nil {
			return fmt.Errorf("ACME challenge listener: %w", err)
		}
		defer challengeListener.Close()
		vault.EnableChallenges()
		challengeServer = &http.Server{Handler: vault.ChallengeHandler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
		defer challengeServer.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reserved := []string{listener.Addr().String()}
	if challengeListener != nil {
		reserved = append(reserved, challengeListener.Addr().String())
	}
	api.EnableFESS(ctx, reserved...)
	defer api.CloseFESS()
	if err := api.EnableTraffic(filepath.Join(*data, "traffic")); err != nil {
		slog.Error("traffic logging unavailable", "error", err)
	}
	var workers sync.WaitGroup
	workers.Add(5)
	go func() { defer workers.Done(); api.RunTraffic(ctx) }()
	go func() { defer workers.Done(); api.RunFeed(ctx) }()
	go func() { defer workers.Done(); api.RunVPNCRLSync(ctx) }()
	go func() { defer workers.Done(); vault.RunACME(ctx) }()
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := vault.TickTLS(); e != nil {
					slog.Error("TLS rollback failed", "error", e)
				}
			}
		}
	}()
	defer func() {
		stop()
		workers.Wait()
		if e := vault.RollbackTLS(); e != nil {
			slog.Error("TLS shutdown rollback failed", "error", e)
		}
	}()
	errch := make(chan error, 2)
	if challengeServer != nil {
		go func() { errch <- challengeServer.Serve(challengeListener) }()
	}
	go func() {
		if *cert != "" {
			errch <- srv.ServeTLS(listener, "", "")
		} else {
			errch <- srv.Serve(listener)
		}
	}()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	slog.Info("GFW started", "url", scheme+"://"+listener.Addr().String(), "admin_token_file", filepath.Join(*data, "admin.token"), "agent_socket", *agent)
	select {
	case err = <-errch:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
func loadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		info, e := os.Stat(path)
		if e != nil {
			return "", e
		}
		if info.Mode().Perm()&0077 != 0 {
			return "", errors.New("admin token must have mode 0600")
		}
		token := strings.TrimSpace(string(b))
		decoded, e := hex.DecodeString(token)
		if e != nil || len(decoded) != 32 {
			return "", errors.New("admin token file is invalid")
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := fmt.Fprintln(f, token)
	syncErr := f.Sync()
	closeErr := f.Close()
	return token, errors.Join(writeErr, syncErr, closeErr)
}
