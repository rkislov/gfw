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
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"testing"
)

func TestSocketPriorityChangesAndResets(t *testing.T) {
	l, err := Listen("127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	for _, priority := range []int{6, 5, 0} {
		require.NoError(t, setPriority(l.conn, priority))
		raw, err := l.conn.SyscallConn()
		require.NoError(t, err)
		var got int
		var optionErr error
		require.NoError(t, raw.Control(func(fd uintptr) { got, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY) }))
		require.NoError(t, optionErr)
		require.Equal(t, priority, got)
	}
	require.Error(t, setPriority(l.conn, -1))
	require.Error(t, setPriority(l.conn, 8))
	require.NoError(t, l.Close())
	require.Error(t, setPriority(l.conn, 5))
}
