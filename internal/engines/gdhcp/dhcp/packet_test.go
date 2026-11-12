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

package dhcp

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRoundTripDiscover(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	p := NewRequest(MsgDiscover, mac, 0x11223344)
	p.Hops = 2
	p.SetBroadcast(true)
	p.GIAddr = netip.MustParseAddr("10.0.0.1")
	p.Set(OptHostname, []byte("printer-01"))
	raw82 := []byte{0x01, 0x0c, 'G', 'i', '0', '/', '1', ':', 'v', 'l', 'a', 'n', '2', '0'}
	p.Add(OptRelayAgent, raw82)

	buf, err := p.Marshal()
	require.NoError(t, err)
	got, err := Parse(buf)
	require.NoError(t, err)

	require.Equal(t, BootRequest, got.Op)
	require.Equal(t, byte(2), got.Hops)
	require.Equal(t, uint32(0x11223344), got.XID)
	require.True(t, got.Broadcast())
	require.Equal(t, "10.0.0.1", got.GIAddr.String())
	require.Equal(t, "aa:bb:cc:dd:ee:ff", got.MAC())
	require.Equal(t, MsgDiscover, got.MessageType())
	require.Equal(t, "printer-01", got.Hostname())
	require.True(t, got.Relayed())
	blobs := got.RelayAgentBlobs()
	require.Len(t, blobs, 1)
	require.True(t, bytes.Equal(raw82, blobs[0]), "option 82 must be echoed byte-for-byte")
}

func TestParseRejectsShortAndBadCookie(t *testing.T) {
	_, err := Parse([]byte{1, 2, 3})
	require.Error(t, err)

	buf := make([]byte, headerLen)
	_, err = Parse(buf)
	require.Error(t, err)
}

func TestConfiguredOptions(t *testing.T) {
	opt, err := ParseConfiguredOption(6, "1.1.1.1, 8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, OptDNS, opt.Code)
	require.Equal(t, []byte{1, 1, 1, 1, 8, 8, 8, 8}, opt.Data)

	opt, err = ParseConfiguredOption(51, "1h")
	require.NoError(t, err)
	require.Equal(t, DurationOption(OptLeaseTime, time.Hour).Data, opt.Data)

	opt, err = ParseConfiguredOption(43, "hex:0102")
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, opt.Data)

	domains := DecodeDomainSearch(EncodeDomainSearch([]string{"lan.local", "example.com"}))
	require.Equal(t, []string{"lan.local", "example.com"}, domains)
}

func TestTruncatedOption(t *testing.T) {
	buf := make([]byte, headerLen+2)
	buf[0] = BootRequest
	buf[1] = HTypeEthernet
	buf[2] = 6
	buf[236], buf[237], buf[238], buf[239] = 99, 130, 83, 99
	buf[240] = OptHostname
	buf[241] = 10
	_, err := Parse(buf)
	require.Error(t, err)
}
