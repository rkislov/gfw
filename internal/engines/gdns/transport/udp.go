// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"fmt"
	"net"
	"runtime"
)

// ListenUDP binds every socket before the service starts. Linux can distribute
// independent client flows between sockets; other platforms keep one listener.
func ListenUDP(address string, configured int) ([]net.PacketConn, error) {
	if configured < 0 || configured > 64 {
		return nil, fmt.Errorf("udp_workers must be 0..64")
	}
	workers := configured
	if workers == 0 {
		workers = 1
		if runtime.GOOS == "linux" {
			workers = min(16, runtime.GOMAXPROCS(0))
		}
	}
	conns := make([]net.PacketConn, 0, workers)
	for i := 0; i < workers; i++ {
		conn, err := listenUDPSocket(address, workers > 1)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}
		conns = append(conns, conn)
		if i == 0 {
			address = conn.LocalAddr().String()
		}
	}
	return conns, nil
}
