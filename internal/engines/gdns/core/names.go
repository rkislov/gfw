// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"github.com/miekg/dns"
	"strings"
)

// withinZone avoids allocating label-index slices for ordinary wire names.
// Escape sequences retain the library's label-boundary semantics; case folding
// is ASCII-only, as required for DNS (not Unicode text case folding).
func withinZone(parent, name string) bool {
	if !strings.HasSuffix(parent, ".") || !strings.HasSuffix(name, ".") || strings.ContainsRune(parent, '\\') || strings.ContainsRune(name, '\\') {
		return dns.IsSubDomain(parent, name)
	}
	if parent == "." {
		return true
	}
	if len(name) < len(parent) {
		return false
	}
	start := len(name) - len(parent)
	if start > 0 && name[start-1] != '.' {
		return false
	}
	for i := range len(parent) {
		a, b := parent[i], name[start+i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
