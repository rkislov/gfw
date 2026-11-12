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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaceName(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		name, err := interfaceName(conn, iface.Index)
		require.NoError(t, err)
		require.Equal(t, iface.Name, name)
	}
	_, err = interfaceName(conn, 0)
	require.Error(t, err)
	_, err = interfaceName(conn, -1)
	require.Error(t, err)
	_, err = interfaceName(conn, 2147483647)
	require.Error(t, err)
}

func BenchmarkInterfaceName(b *testing.B) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		b.Fatal("no interfaces", err)
	}
	index := ifaces[0].Index
	b.Run("standard", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := net.InterfaceByIndex(index); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("datagram", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := interfaceName(conn, index); err != nil {
				b.Fatal(err)
			}
		}
	})
}
