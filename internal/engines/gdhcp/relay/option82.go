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
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	SubCircuitID     byte = 1
	SubRemoteID      byte = 2
	SubLinkSelection byte = 5
	SubVSS           byte = 151
	SubNested        byte = 152
)

// SubOption is one relay-agent sub-option.
type SubOption struct {
	Code byte
	Data []byte
}

// Info is a parsed option 82 body. Raw is the original payload and is what
// must be echoed unchanged (RFC 3046 §2.2).
type Info struct {
	Raw           []byte
	CircuitID     []byte
	RemoteID      []byte
	LinkSelection netip.Addr
	VSS           []byte
	Nested        []*Info
	Subs          []SubOption
}

// CircuitIDString returns a printable circuit id, or a hex dump when the
// value is not text.
func (n *Info) CircuitIDString() string {
	return printable(n.CircuitID)
}

func (n *Info) RemoteIDString() string {
	return printable(n.RemoteID)
}

// Parse walks sub-options. Sub-option 152 is treated as a nested option 82
// body (multi-hop, RFC 4243-style encapsulation used by the project contract).
func Parse(data []byte) (*Info, error) {
	info := &Info{Raw: append([]byte(nil), data...)}
	if err := parseInto(data, info, 0); err != nil {
		return nil, err
	}
	return info, nil
}

func parseInto(data []byte, info *Info, depth int) error {
	if depth > 8 {
		return fmt.Errorf("relay: option 82 nested too deep")
	}
	for i := 0; i < len(data); {
		if i+1 >= len(data) {
			return fmt.Errorf("relay: truncated sub-option")
		}
		code := data[i]
		n := int(data[i+1])
		if i+2+n > len(data) {
			return fmt.Errorf("relay: truncated sub-option %d", code)
		}
		payload := append([]byte(nil), data[i+2:i+2+n]...)
		info.Subs = append(info.Subs, SubOption{Code: code, Data: payload})
		switch code {
		case SubCircuitID:
			if info.CircuitID == nil {
				info.CircuitID = payload
			}
		case SubRemoteID:
			if info.RemoteID == nil {
				info.RemoteID = payload
			}
		case SubLinkSelection:
			if n == 4 {
				var a [4]byte
				copy(a[:], payload)
				info.LinkSelection = netip.AddrFrom4(a)
			}
		case SubVSS:
			info.VSS = payload
		case SubNested:
			nested := &Info{Raw: payload}
			if err := parseInto(payload, nested, depth+1); err != nil {
				return err
			}
			info.Nested = append(info.Nested, nested)
		}
		i += 2 + n
	}
	return nil
}

// WalkCircuitIDs returns circuit IDs from the client side outward: the first
// relay (closest to the client) is returned first.
func WalkCircuitIDs(infos []*Info) [][]byte {
	var out [][]byte
	var walk func(*Info)
	walk = func(n *Info) {
		if n == nil {
			return
		}
		if len(n.CircuitID) > 0 {
			out = append(out, n.CircuitID)
		}
		for _, c := range n.Nested {
			walk(c)
		}
	}
	for _, n := range infos {
		walk(n)
	}
	return out
}

// FirstRemoteID returns the first remote id found.
func FirstRemoteID(infos []*Info) []byte {
	for _, n := range infos {
		if id := remoteOf(n); len(id) > 0 {
			return id
		}
	}
	return nil
}

func remoteOf(n *Info) []byte {
	if n == nil {
		return nil
	}
	if len(n.RemoteID) > 0 {
		return n.RemoteID
	}
	for _, c := range n.Nested {
		if id := remoteOf(c); len(id) > 0 {
			return id
		}
	}
	return nil
}

// FirstLinkSelection returns the first sub-option 5 address.
func FirstLinkSelection(infos []*Info) netip.Addr {
	for _, n := range infos {
		if a := linkOf(n); a.IsValid() {
			return a
		}
	}
	return netip.Addr{}
}

func linkOf(n *Info) netip.Addr {
	if n == nil {
		return netip.Addr{}
	}
	if n.LinkSelection.IsValid() {
		return n.LinkSelection
	}
	for _, c := range n.Nested {
		if a := linkOf(c); a.IsValid() {
			return a
		}
	}
	return netip.Addr{}
}

// EncodeSub builds a sub-option.
func EncodeSub(code byte, data []byte) []byte {
	b := make([]byte, 2+len(data))
	b[0] = code
	b[1] = byte(len(data))
	copy(b[2:], data)
	return b
}

// EncodeLinkSelection encodes sub-option 5.
func EncodeLinkSelection(ip netip.Addr) []byte {
	a := ip.As4()
	return EncodeSub(SubLinkSelection, a[:])
}

func printable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "0x" + hexBytes(b)
		}
	}
	return string(b)
}

func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// BinaryVLAN tries common binary circuit-id layouts (Cisco-style).
func BinaryVLAN(circuit []byte) (int, bool) {
	switch len(circuit) {
	case 2:
		v := int(binary.BigEndian.Uint16(circuit))
		if v >= 1 && v <= 4094 {
			return v, true
		}
	case 4:
		v := int(binary.BigEndian.Uint16(circuit[:2]))
		if v >= 1 && v <= 4094 {
			return v, true
		}
	}
	return 0, false
}
