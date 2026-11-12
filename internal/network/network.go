// Package network exposes read-only host inventory. No links are mutated.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"
)

type Interface struct {
	Index     int      `json:"index"`
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}

func Inventory() ([]Interface, error) {
	links, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(links))
	for _, l := range links {
		addrs, err := l.Addrs()
		if err != nil {
			return nil, fmt.Errorf("%s addresses: %w", l.Name, err)
		}
		addresses := []string{}
		for _, a := range addrs {
			addresses = append(addresses, a.String())
		}
		sort.Strings(addresses)
		out = append(out, Interface{l.Index, l.Name, l.MTU, l.HardwareAddr.String(), l.Flags&net.FlagUp != 0, l.Flags&net.FlagLoopback != 0, addresses})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// FromAgent uses only a local Unix socket. A configured but unavailable agent
// is an error; it must never silently display the controller host's interfaces.
func FromAgent(ctx context.Context, socket string) ([]Interface, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://agent/v1/interfaces", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("agent status %d", resp.StatusCode)
	}
	var out []Interface
	err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&out)
	return out, err
}
