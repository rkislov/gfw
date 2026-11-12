// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Linux maps skb priority to the VLAN tag using the interface's egress-qos-map.
// The listener has one writer, so changing SO_PRIORITY cannot race another reply.
func setPriority(conn *net.UDPConn, priority int) error {
	if priority < 0 || priority > 7 {
		return fmt.Errorf("invalid PCP %d", priority)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY, priority) }); err != nil {
		return err
	}
	return optionErr
}
