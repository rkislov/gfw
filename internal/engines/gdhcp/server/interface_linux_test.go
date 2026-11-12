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
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestInterfaceNameTracksRename(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("gdt%d", os.Getpid())}}
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("requires CAP_NET_ADMIN in an isolated namespace")
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, netlink.LinkDel(link)) })
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	name, err := interfaceName(conn, link.Index)
	require.NoError(t, err)
	require.Equal(t, link.Name, name)
	renamed := fmt.Sprintf("gdr%d", os.Getpid())
	require.NoError(t, netlink.LinkSetName(link, renamed))
	name, err = interfaceName(conn, link.Index)
	require.NoError(t, err)
	require.Equal(t, renamed, name)
	require.NoError(t, conn.Close())
	_, err = interfaceName(conn, link.Index)
	require.Error(t, err)
}
