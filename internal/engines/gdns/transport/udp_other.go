//go:build !linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"fmt"
	"net"
)

func listenUDPSocket(address string, reuse bool) (net.PacketConn, error) {
	if reuse {
		return nil, fmt.Errorf("multiple UDP workers require Linux; select udp_workers=0 or 1")
	}
	return net.ListenPacket("udp", address)
}
