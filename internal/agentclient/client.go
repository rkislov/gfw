// Package agentclient uses a local Unix socket only, never a user-controlled URL.
package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }
func Call(ctx context.Context, socket, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	transport := unixTransport(socket)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reader := io.LimitReader(resp.Body, 8<<20)
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		if err = json.NewDecoder(reader).Decode(&e); err != nil {
			return fmt.Errorf("agent status %d", resp.StatusCode)
		}
		return &Error{resp.StatusCode, e.Error}
	}
	return json.NewDecoder(reader).Decode(out)
}

func unixTransport(socket string) *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
}

// Open streams a response from the trusted agent. The caller closes its body.
func Open(ctx context.Context, socket, method, path string, headers http.Header) (*http.Response, error) {
	transport := unixTransport(socket)
	transport.DisableKeepAlives = true
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, nil)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"Range", "If-Range"} {
		if value := headers.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}
	return client.Do(req)
}
