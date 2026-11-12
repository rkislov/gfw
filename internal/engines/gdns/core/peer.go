// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"net"
	"net/netip"
)

// ClientIP uses the actual socket peer, without formatting and reparsing common
// UDP/TCP addresses. Proxy headers and EDNS Client Subnet never enter this path.
func ClientIP(addr net.Addr) netip.Addr {
	switch peer := addr.(type) {
	case *net.UDPAddr:
		return peer.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return peer.AddrPort().Addr().Unmap()
	}
	if addr == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}
