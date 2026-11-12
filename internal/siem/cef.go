// Package siem formats CEF events and sends them over octet-counted syslog.
package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Field struct {
	Key, Value string
}

var headerEscape = strings.NewReplacer("\\", "\\\\", "|", "\\|")
var valueEscape = strings.NewReplacer("\\", "\\\\", "=", "\\=", "\r", "\\r", "\n", "\\n")

func Event(host, at, version, code, name string, severity int, fields ...Field) string {
	timestamp, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		timestamp = time.Now().UTC()
	}
	host = strings.TrimSpace(host)
	if len(host) > 255 || strings.ContainsFunc(host, func(r rune) bool { return r < 33 || r > 126 }) || host == "" {
		host = "-"
	}
	var out strings.Builder
	fmt.Fprintf(&out, "<134>1 %s %s gfw - - - CEF:0|GFW|GFW NGFW|%s|%s|%s|%d|",
		timestamp.UTC().Format("2006-01-02T15:04:05.999999Z07:00"), host, header(version), header(code), header(name), severity)
	for i, field := range fields {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(field.Key + "=" + valueEscape.Replace(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) && r != '\r' && r != '\n' {
				return ' '
			}
			return r
		}, field.Value)))
	}
	return out.String()
}

func header(s string) string {
	return headerEscape.Replace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

type Destination struct {
	Address, Transport, CA string
}

func (d Destination) tlsConfig() (*tls.Config, error) {
	if d.Transport != "tls" && d.Transport != "tcp" {
		return nil, errors.New("выберите TCP или TLS")
	}
	host, port, err := net.SplitHostPort(d.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#@%") ||
		strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || portErr != nil || portNumber == 0 {
		return nil, errors.New("укажите адрес SIEM в формате хост:порт")
	}
	if d.Transport == "tcp" {
		if d.CA != "" {
			return nil, errors.New("CA используется только с TLS")
		}
		return nil, nil
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if d.CA != "" {
		cfg.RootCAs = x509.NewCertPool()
		if len(d.CA) > 64<<10 || !cfg.RootCAs.AppendCertsFromPEM([]byte(d.CA)) {
			return nil, errors.New("неверный сертификат CA в PEM")
		}
	}
	return cfg, nil
}

func (d Destination) Validate() error {
	_, err := d.tlsConfig()
	return err
}

func (d Destination) Send(ctx context.Context, messages []string) error {
	if len(messages) == 0 {
		return nil
	}
	cfg, err := d.tlsConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{}
	var conn net.Conn
	if cfg == nil {
		conn, err = dialer.DialContext(ctx, "tcp", d.Address)
	} else {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", d.Address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	for _, message := range messages {
		frame := strconv.Itoa(len(message)) + " " + message
		if n, err := io.WriteString(conn, frame); err != nil {
			return err
		} else if n != len(frame) {
			return io.ErrShortWrite
		}
	}
	return nil
}
