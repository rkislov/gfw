// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDDNSValidation(t *testing.T) {
	c := &Config{DDNS: DDNS{Enabled: true, Server: "dc.example.org", Zone: "hosts.example.org", Principal: "dhcp-dns@EXAMPLE.ORG", Keytab: "/etc/godhcp/dns.keytab", ReverseZones: []string{"2.0.192.in-addr.arpa"}}}
	c.ApplyDefaults()
	require.NoError(t, ValidateDDNS(c.DDNS))
	for name, mutate := range map[string]func(*DDNS){
		"zone":            func(d *DDNS) { d.Zone = "example.org\nsend" },
		"server":          func(d *DDNS) { d.Server = "dc.example.org:53" },
		"principal":       func(d *DDNS) { d.Principal = "--help@REALM" },
		"keytab":          func(d *DDNS) { d.Keytab = "relative" },
		"auth":            func(d *DDNS) { d.Auth = "none" },
		"reverse":         func(d *DDNS) { d.ReverseZones = []string{"0-127.2.0.192.in-addr.arpa"} },
		"missing-reverse": func(d *DDNS) { d.ReverseZones = nil },
		"no-records":      func(d *DDNS) { no := false; d.UpdateA = &no; d.UpdatePTR = &no },
		"timeout":         func(d *DDNS) { d.TimeoutSeconds = 61 },
	} {
		t.Run(name, func(t *testing.T) { d := c.DDNS; mutate(&d); require.Error(t, ValidateDDNS(d)) })
	}
	d := c.DDNS
	d.Auth = "tsig"
	d.KeyFile = "/etc/godhcp/dns.key"
	require.NoError(t, ValidateDDNS(d))
}
