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

package relay

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVendorParsers(t *testing.T) {
	parsers := BuiltinParsers()
	cases := []struct {
		id   string
		vlan int
		name string
	}{
		{"Gi0/1:vlan20", 20, "cisco"},
		{"slot=0;subslot=0;GE0/0/1;vlanid=30", 30, "huawei"},
		{"bridge:10", 10, "mikrotik"},
		{"vlan20", 20, "aruba"},
		{"1:2:30", 30, "extreme"},
		{"ge-0/0/1.0:vlan-id20", 20, "juniper"},
		{"1/1/1/vlan30", 30, "brocade"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			vlan, name, _, ok := MatchVLAN(parsers, tc.id, "")
			require.True(t, ok)
			require.Equal(t, tc.vlan, vlan)
			require.Equal(t, tc.name, name)
		})
	}
}

func TestBrokenCircuitFallsThrough(t *testing.T) {
	nets := sampleNets()
	dec, ok := Resolve(nil, BuiltinParsers(), nets, []Route{{
		GIAddr:   "192.168.30.1",
		SubnetID: "guest-wifi",
	}}, Request{
		CircuitID: "not a circuit",
		GIAddr:    netip.MustParseAddr("192.168.30.1"),
	})
	require.True(t, ok)
	require.Equal(t, "guest-wifi", dec.SubnetID)
	require.Equal(t, SourceGIAddr, dec.Source)
}

func TestLinkSelectionWinsOverGIAddr(t *testing.T) {
	nets := sampleNets()
	dec, ok := Resolve(nil, BuiltinParsers(), nets, nil, Request{
		LinkSelection: netip.MustParseAddr("192.168.20.1"),
		GIAddr:        netip.MustParseAddr("10.0.0.1"),
		CircuitID:     "",
	})
	require.True(t, ok)
	require.Equal(t, "voip-phones", dec.SubnetID)
	require.Equal(t, SourceLinkSelection, dec.Source)
}

func TestCiscoCircuitSelectsVLAN(t *testing.T) {
	dec, ok := Resolve(nil, BuiltinParsers(), sampleNets(), nil, Request{
		CircuitID: "Gi0/1:vlan20",
		GIAddr:    netip.MustParseAddr("10.0.0.1"),
	})
	require.True(t, ok)
	require.Equal(t, "voip-phones", dec.SubnetID)
	require.Equal(t, 20, *dec.VLAN)
	require.Equal(t, "cisco", dec.Parser)
}

func TestUnknownVLANStopsWalk(t *testing.T) {
	dec, ok := Resolve(nil, BuiltinParsers(), sampleNets(), []Route{{
		GIAddr: "192.168.10.1", VLAN: pint(10),
	}}, Request{
		CircuitID: "Gi0/1:vlan99",
		GIAddr:    netip.MustParseAddr("192.168.10.1"),
	})
	require.False(t, ok)
	require.True(t, dec.UnknownVLAN)
	require.Equal(t, 99, dec.UnknownID)
}

func TestNestedOption82NearestCircuit(t *testing.T) {
	inner := append(EncodeSub(SubCircuitID, []byte("bridge:30")), EncodeSub(SubRemoteID, []byte("relay-inner"))...)
	outer := append(EncodeSub(SubCircuitID, []byte("Gi0/1:vlan20")), EncodeSub(SubRemoteID, []byte("relay-01"))...)
	outer = append(outer, EncodeSub(SubNested, inner)...)
	info, err := Parse(outer)
	require.NoError(t, err)
	ids := WalkCircuitIDs([]*Info{info})
	require.Equal(t, []string{"Gi0/1:vlan20", "bridge:30"}, []string{string(ids[0]), string(ids[1])})
	require.Equal(t, "relay-01", string(FirstRemoteID([]*Info{info})))

	vlan, name, _, ok := MatchVLAN(BuiltinParsers(), string(ids[0]), "")
	require.True(t, ok)
	require.Equal(t, 20, vlan)
	require.Equal(t, "cisco", name)
}

func TestEchoRawUntouched(t *testing.T) {
	raw := []byte{1, 12, 'G', 'i', '0', '/', '1', ':', 'v', 'l', 'a', 'n', '2', '0', 2, 8, 'r', 'e', 'l', 'a', 'y', '-', '0', '1'}
	info, err := Parse(raw)
	require.NoError(t, err)
	require.Equal(t, raw, info.Raw)
	require.Equal(t, "Gi0/1:vlan20", info.CircuitIDString())
	require.Equal(t, "relay-01", info.RemoteIDString())
}

func TestLinkSelectionSuboption(t *testing.T) {
	body := EncodeLinkSelection(netip.MustParseAddr("192.168.20.1"))
	info, err := Parse(body)
	require.NoError(t, err)
	require.Equal(t, "192.168.20.1", info.LinkSelection.String())
	require.Equal(t, body, info.Raw)
}

func sampleNets() []Network {
	return []Network{
		{ID: "office-lan", VLAN: pint(10), Prefix: netip.MustParsePrefix("192.168.10.0/24")},
		{ID: "voip-phones", VLAN: pint(20), Prefix: netip.MustParsePrefix("192.168.20.0/24"), LinkSelection: netip.MustParseAddr("192.168.20.1")},
		{ID: "guest-wifi", VLAN: pint(30), Prefix: netip.MustParsePrefix("192.168.30.0/24")},
	}
}

func pint(v int) *int { return &v }

func TestDomesticVendorFormatsAndStrictSelection(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		vlan        int
	}{
		{"eltex", "esr01 eth 1/0/1:120", 120},
		{"eltex", "eth 1/8:4094", 4094},
		{"qtech", "vlan120+Ethernet1/0/8", 120},
	} {
		v, name, _, ok := MatchVLAN(BuiltinParsers(), tc.input, "")
		require.True(t, ok, tc.input)
		require.Equal(t, tc.vlan, v)
		require.Equal(t, tc.name, name)
	}
	for _, input := range []string{"eth 1/8:0", "eth 1/8:4095", "eth 1/8:120garbage", "vlan4095+Ethernet1/0/8"} {
		_, _, _, ok := MatchVLAN(BuiltinParsers(), input, "eltex")
		require.False(t, ok, input)
	}
	_, _, _, ok := MatchVLAN(BuiltinParsers(), "bridge:10", "eltex")
	require.False(t, ok)
	_, _, _, ok = MatchVLAN(BuiltinParsers(), "bridge:10", "unknown")
	require.False(t, ok)
	for _, profile := range Profiles() {
		if profile.Pattern == "" {
			continue
		}
		p, err := Compile(profile.Name, profile.Pattern, "vlan")
		require.NoError(t, err)
		_, _, ok := p.Parse(profile.Example)
		require.True(t, ok, profile.Name)
	}
}
