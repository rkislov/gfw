// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/tls"
	"github.com/rkislov/gfw/internal/engines/gdns/core"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

type Servers struct {
	dot                      *dns.Server
	doh                      *http.Server
	dotListener, dohListener net.Listener
}

func Listen(c core.Config, e *core.Engine) (*Servers, error) { return ListenWithAdmin(c, e, nil) }

// ListenWithAdmin exposes the authenticated admin UI on the native DoH HTTPS
// listener, preserving the real peer address for DNS policies without a proxy.
func ListenWithAdmin(c core.Config, e *core.Engine, admin http.Handler) (*Servers, error) {
	s := &Servers{}
	if c.DoHListen == "" && c.DoTListen == "" {
		return s, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if c.DoTListen != "" {
		l, err := net.Listen("tcp", c.DoTListen)
		if err != nil {
			return nil, err
		}
		s.dotListener = tls.NewListener(l, cfg.Clone())
		s.dot = &dns.Server{Listener: s.dotListener, TsigProvider: e, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { e.ServeDNSAs(w, q, "dot") }), ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 30 * time.Second }, MaxTCPQueries: -1}
	}
	if c.DoHListen != "" {
		s.dohListener, err = net.Listen("tcp", c.DoHListen)
		if err != nil {
			if s.dotListener != nil {
				s.dotListener.Close()
			}
			return nil, err
		}
		handler := DoHHandler(e)
		if admin != nil {
			mux := http.NewServeMux()
			mux.Handle("/dns-query", handler)
			mux.Handle("/", admin)
			handler = mux
		}
		s.doh = &http.Server{ConnContext: peerContext, TLSConfig: cfg.Clone(), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	}
	return s, nil
}
func (s *Servers) Start(errs chan<- error) {
	if s.dot != nil {
		go func() { errs <- s.dot.ActivateAndServe() }()
	}
	if s.doh != nil {
		go func() { errs <- s.doh.ServeTLS(s.dohListener, "", "") }()
	}
}
func (s *Servers) Shutdown(ctx context.Context) {
	if s.dot != nil {
		_ = s.dot.ShutdownContext(ctx)
	}
	if s.doh != nil {
		_ = s.doh.Shutdown(ctx)
	}
	s.Close()
}
func (s *Servers) Close() {
	if s.dotListener != nil {
		_ = s.dotListener.Close()
	}
	if s.dohListener != nil {
		_ = s.dohListener.Close()
	}
}
