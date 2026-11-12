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

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// interfaceName avoids InterfaceByIndex's netlink dump and large temporary
// buffers on every DHCP datagram. Query the current name; never cache a mapping
// across interface renames or deletion/reuse of an index.
func interfaceName(conn *net.UDPConn, index int) (string, error) {
	if index <= 0 || uint64(index) > uint64(^uint32(0)) {
		return "", fmt.Errorf("invalid interface index %d", index)
	}
	req, err := unix.NewIfreq("")
	if err != nil {
		return "", err
	}
	req.SetUint32(uint32(index))
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var queryErr error
	if err = raw.Control(func(fd uintptr) { queryErr = unix.IoctlIfreq(int(fd), unix.SIOCGIFNAME, req) }); err != nil {
		return "", err
	}
	if queryErr != nil {
		return "", queryErr
	}
	return req.Name(), nil
}
