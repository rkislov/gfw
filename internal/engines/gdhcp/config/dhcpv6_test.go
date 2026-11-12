// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestValidateIPv6Pools(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*DHCPv6)
	}{
		{"reversed", func(c *DHCPv6) { c.Pools[0].End = "fd12::9" }},
		{"outside", func(c *DHCPv6) { c.Pools[0].End = "fd13::1" }},
		{"overlap", func(c *DHCPv6) { c.Pools = append(c.Pools, c.Pools[0]) }},
		{"wrong-family", func(c *DHCPv6) { c.DNS = []string{"192.0.2.1"} }},
		{"client-multicast", func(c *DHCPv6) { c.Listen = "[fd12::1]:547" }},
		{"relay", func(c *DHCPv6) { c.Pools[0].Relays = []string{"ff02::1"} }},
		{"invalid-duid", func(c *DHCPv6) { c.ServerDUID = "not-hex" }},
		{"lifetimes", func(c *DHCPv6) { c.Preferred = c.Valid + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{DHCPv6: DHCPv6{Enabled: true, Pools: []IPv6Pool{{Interface: "lan0", Prefix: "fd12::/64", Start: "fd12::10", End: "fd12::ff"}}}}
			cfg.ApplyDefaults()
			if err := cfg.DHCPv6.Validate(); err != nil {
				t.Fatal(err)
			}
			tc.edit(&cfg.DHCPv6)
			if err := cfg.DHCPv6.Validate(); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
