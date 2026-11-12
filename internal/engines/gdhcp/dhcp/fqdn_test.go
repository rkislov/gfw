// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dhcp

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClientFQDNEncodingAndHostnamePrecedence(t *testing.T) {
	for _, flags := range []byte{0, FQDNEncoded, FQDNServer | FQDNEncoded} {
		for _, name := range []string{"host", "host.example.org.", ""} {
			p := &Packet{}
			p.Set(OptHostname, []byte("old-name"))
			p.Append(FQDNOption(flags, name))
			got, ok := p.ClientFQDN()
			require.True(t, ok)
			require.Equal(t, name, got.Name)
			require.Equal(t, flags, got.Flags)
			require.Equal(t, name, p.Hostname())
		}
	}
	p := &Packet{}
	p.Set(OptHostname, []byte("fallback"))
	p.Append(FQDNOption(FQDNNoUpdate|FQDNEncoded, "client.example.org."))
	require.Empty(t, p.Hostname())
	for _, bad := range [][]byte{{4}, {4, 0, 0, 0xc0, 0x0c}, {4, 0, 0, 5, 'x'}, {4, 0, 0, 0, 'x'}, {4, 0, 0, 3, 'a', '.', 'b', 0}} {
		p.Set(OptClientFQDN, bad)
		_, ok := p.ClientFQDN()
		require.False(t, ok)
	}
}
