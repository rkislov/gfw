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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// NewRequest builds a BOOTREQUEST with the given message type and MAC.
func NewRequest(mt byte, mac net.HardwareAddr, xid uint32) *Packet {
	hw := make(net.HardwareAddr, 16)
	copy(hw, mac)
	p := &Packet{
		Op:     BootRequest,
		HType:  HTypeEthernet,
		HLen:   6,
		XID:    xid,
		CHAddr: hw,
	}
	p.Set(OptMessageType, []byte{mt})
	return p
}

func IPOption(code byte, ips ...netip.Addr) Option {
	buf := make([]byte, 0, 4*len(ips))
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		b := ip.As4()
		buf = append(buf, b[:]...)
	}
	return Option{Code: code, Data: buf}
}

func DurationOption(code byte, d time.Duration) Option {
	sec := uint32(d / time.Second)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], sec)
	return Option{Code: code, Data: b[:]}
}

func StringOption(code byte, s string) Option {
	return Option{Code: code, Data: []byte(s)}
}

func ByteOption(code byte, v byte) Option {
	return Option{Code: code, Data: []byte{v}}
}

// EncodeDomainSearch encodes option 119 (RFC 3397) without compression.
func EncodeDomainSearch(domains []string) []byte {
	var b []byte
	for _, d := range domains {
		d = strings.Trim(d, ".")
		if d == "" {
			continue
		}
		for _, label := range strings.Split(d, ".") {
			if len(label) > 63 {
				label = label[:63]
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
		b = append(b, 0)
	}
	return b
}

// DecodeDomainSearch decodes option 119 without following compression pointers.
func DecodeDomainSearch(b []byte) []string {
	var out []string
	for i := 0; i < len(b); {
		var labels []string
		for i < len(b) {
			n := int(b[i])
			i++
			if n == 0 {
				break
			}
			if n > 63 || i+n > len(b) {
				return out
			}
			labels = append(labels, string(b[i:i+n]))
			i += n
		}
		if len(labels) > 0 {
			out = append(out, strings.Join(labels, "."))
		}
	}
	return out
}

// ParseConfiguredOption converts a YAML option value into wire bytes.
// Strings may be an IP, a comma-separated IP list, a duration (for 51/58/59),
// or raw bytes prefixed with "hex:".
func ParseConfiguredOption(code int, value string) (Option, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "hex:") {
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "hex:"))
		if err != nil {
			return Option{}, fmt.Errorf("option %d: %w", code, err)
		}
		return Option{Code: byte(code), Data: raw}, nil
	}
	switch byte(code) {
	case OptSubnetMask, OptRouter, OptDNS, OptNTP, OptServerID, OptTFTPServerAddr, OptRequestedIP:
		ips, err := parseIPList(value)
		if err != nil {
			return Option{}, fmt.Errorf("option %d: %w", code, err)
		}
		return IPOption(byte(code), ips...), nil
	case OptLeaseTime, OptRenewalTime, OptRebindingTime:
		sec, err := parseSeconds(value)
		if err != nil {
			return Option{}, fmt.Errorf("option %d: %w", code, err)
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], sec)
		return Option{Code: byte(code), Data: b[:]}, nil
	case OptDomainSearch:
		parts := splitList(value)
		return Option{Code: OptDomainSearch, Data: EncodeDomainSearch(parts)}, nil
	default:
		return StringOption(byte(code), value), nil
	}
}

func parseIPList(value string) ([]netip.Addr, error) {
	parts := splitList(value)
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		ip, err := netip.ParseAddr(p)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid IPv4 %q", p)
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty address list")
	}
	return out, nil
}

func parseSeconds(value string) (uint32, error) {
	if n, err := strconv.ParseUint(value, 10, 32); err == nil {
		return uint32(n), nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("negative duration")
	}
	return uint32(d / time.Second), nil
}

func splitList(value string) []string {
	value = strings.ReplaceAll(value, ";", ",")
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 && strings.TrimSpace(value) != "" {
		return []string{strings.TrimSpace(value)}
	}
	return out
}
