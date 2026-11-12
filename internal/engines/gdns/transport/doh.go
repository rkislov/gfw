// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/base64"
	"github.com/rkislov/gfw/internal/engines/gdns/core"
	"github.com/miekg/dns"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
)

// The context value is set from net.Conn, once per HTTP/2 connection.
// It is private to this package and cannot be supplied by an HTTP header.
type peerIPKey struct{}

func peerContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, peerIPKey{}, core.ClientIP(conn.RemoteAddr()))
}

// DoHHandler serves RFC 8484 wire-format requests. It is mounted on a dedicated
// TLS listener, separate from the admin API. Proxy headers never determine views.
func DoHHandler(engine *core.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path != "/dns-query" {
			http.NotFound(w, r)
			return
		}
		var data []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			values, ok := r.URL.Query()["dns"]
			if !ok || len(values) != 1 || len(values[0]) > 87380 {
				http.Error(w, "invalid dns parameter", 400)
				return
			}
			data, err = base64.RawURLEncoding.DecodeString(values[0])
		case http.MethodPost:
			typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if e != nil || typ != "application/dns-message" {
				http.Error(w, "expected application/dns-message", 415)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 65535)
			data, err = io.ReadAll(r.Body)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		if err != nil || len(data) < 12 || len(data) > 65535 {
			http.Error(w, "invalid DNS wire message", 400)
			return
		}
		q := new(dns.Msg)
		if err = q.Unpack(data); err != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
			http.Error(w, "invalid DNS query", 400)
			return
		}
		ip, ok := r.Context().Value(peerIPKey{}).(netip.Addr)
		if !ok {
			host, _, peerErr := net.SplitHostPort(r.RemoteAddr)
			if peerErr != nil {
				http.Error(w, "invalid peer address", 400)
				return
			}
			ip, peerErr = netip.ParseAddr(host)
			if peerErr != nil {
				http.Error(w, "invalid peer address", 400)
				return
			}
		}
		if !ip.IsValid() {
			http.Error(w, "invalid peer address", 400)
			return
		}
		answer := engine.AnswerAs(r.Context(), q, ip.Unmap(), "doh")
		wire, err := answer.Pack()
		if err != nil {
			http.Error(w, "failed to encode DNS response", 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(200)
		_, _ = w.Write(wire)
	})
}
