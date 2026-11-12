//go:build linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func listenUDPSocket(address string, reuse bool) (net.PacketConn, error) {
	config := net.ListenConfig{}
	if reuse {
		config.Control = func(_, _ string, raw syscall.RawConn) error {
			var optionErr error
			err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
			if err != nil {
				return err
			}
			return optionErr
		}
	}
	return config.ListenPacket(context.Background(), "udp", address)
}
