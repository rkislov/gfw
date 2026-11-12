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
)

const (
	BootRequest byte = 1
	BootReply   byte = 2

	HTypeEthernet byte = 1

	MagicCookie uint32 = 0x63825363

	flagBroadcast uint16 = 0x8000

	headerLen = 240
)

const (
	MsgDiscover byte = 1
	MsgOffer    byte = 2
	MsgRequest  byte = 3
	MsgDecline  byte = 4
	MsgAck      byte = 5
	MsgNak      byte = 6
	MsgRelease  byte = 7
	MsgInform   byte = 8
)

const (
	OptPad            byte = 0
	OptSubnetMask     byte = 1
	OptRouter         byte = 3
	OptDNS            byte = 6
	OptHostname       byte = 12
	OptDomainName     byte = 15
	OptNTP            byte = 42
	OptVendorSpecific byte = 43
	OptRequestedIP    byte = 50
	OptLeaseTime      byte = 51
	OptMessageType    byte = 53
	OptServerID       byte = 54
	OptParamRequest   byte = 55
	OptMessage        byte = 56
	OptMaxMessageSize byte = 57
	OptRenewalTime    byte = 58
	OptRebindingTime  byte = 59
	OptVendorClass    byte = 60
	OptClientID       byte = 61
	OptTFTPServer     byte = 66
	OptBootfileName   byte = 67
	OptRelayAgent     byte = 82
	OptDomainSearch   byte = 119
	OptClasslessRoute byte = 121
	OptTFTPServerAddr byte = 150
	OptWPAD           byte = 252
	OptEnd            byte = 255
)

// Option is a single DHCP option. Data is owned by the packet.
type Option struct {
	Code byte
	Data []byte
}

// Packet is a DHCPv4 message (RFC 2131).
type Packet struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  netip.Addr
	YIAddr  netip.Addr
	SIAddr  netip.Addr
	GIAddr  netip.Addr
	CHAddr  net.HardwareAddr
	SName   string
	File    string
	Options []Option
}

func MessageName(t byte) string {
	switch t {
	case MsgDiscover:
		return "DISCOVER"
	case MsgOffer:
		return "OFFER"
	case MsgRequest:
		return "REQUEST"
	case MsgDecline:
		return "DECLINE"
	case MsgAck:
		return "ACK"
	case MsgNak:
		return "NAK"
	case MsgRelease:
		return "RELEASE"
	case MsgInform:
		return "INFORM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// Parse decodes a DHCPv4 packet. Option 82 payloads are preserved byte-for-byte.
func Parse(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("dhcp: packet too short: %d", len(b))
	}
	cookie := binary.BigEndian.Uint32(b[236:240])
	if cookie != MagicCookie {
		return nil, fmt.Errorf("dhcp: bad magic cookie %#x", cookie)
	}
	p := &Packet{
		Op:     b[0],
		HType:  b[1],
		HLen:   b[2],
		Hops:   b[3],
		XID:    binary.BigEndian.Uint32(b[4:8]),
		Secs:   binary.BigEndian.Uint16(b[8:10]),
		Flags:  binary.BigEndian.Uint16(b[10:12]),
		CIAddr: addr4(b[12:16]),
		YIAddr: addr4(b[16:20]),
		SIAddr: addr4(b[20:24]),
		GIAddr: addr4(b[24:28]),
		CHAddr: append(net.HardwareAddr(nil), b[28:44]...),
		SName:  cString(b[44:108]),
		File:   cString(b[108:236]),
	}
	opts, err := parseOptions(b[240:])
	if err != nil {
		return nil, err
	}
	p.Options = opts
	return p, nil
}

// Marshal encodes the packet. Options are written in slice order and terminated by 255.
func (p *Packet) Marshal() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("dhcp: nil packet")
	}
	opts := make([]byte, 0, 128)
	for _, o := range p.Options {
		if o.Code == OptPad || o.Code == OptEnd {
			continue
		}
		if len(o.Data) > 255 {
			return nil, fmt.Errorf("dhcp: option %d exceeds 255 bytes", o.Code)
		}
		opts = append(opts, o.Code, byte(len(o.Data)))
		opts = append(opts, o.Data...)
	}
	opts = append(opts, OptEnd)
	buf := make([]byte, headerLen+len(opts))
	buf[0] = p.Op
	buf[1] = p.HType
	if buf[1] == 0 {
		buf[1] = HTypeEthernet
	}
	buf[2] = p.HLen
	buf[3] = p.Hops
	binary.BigEndian.PutUint32(buf[4:8], p.XID)
	binary.BigEndian.PutUint16(buf[8:10], p.Secs)
	binary.BigEndian.PutUint16(buf[10:12], p.Flags)
	putAddr(buf[12:16], p.CIAddr)
	putAddr(buf[16:20], p.YIAddr)
	putAddr(buf[20:24], p.SIAddr)
	putAddr(buf[24:28], p.GIAddr)
	n := int(p.HLen)
	if n <= 0 {
		n = 6
	}
	if n > 16 {
		n = 16
	}
	if len(p.CHAddr) < n {
		return nil, fmt.Errorf("dhcp: chaddr shorter than hlen")
	}
	copy(buf[28:44], p.CHAddr[:n])
	putCString(buf[44:108], p.SName)
	putCString(buf[108:236], p.File)
	binary.BigEndian.PutUint32(buf[236:240], MagicCookie)
	copy(buf[240:], opts)
	return buf, nil
}

func (p *Packet) MessageType() byte {
	d, ok := p.Get(OptMessageType)
	if !ok || len(d) < 1 {
		return 0
	}
	return d[0]
}

func (p *Packet) Get(code byte) ([]byte, bool) {
	for _, o := range p.Options {
		if o.Code == code {
			return o.Data, true
		}
	}
	return nil, false
}

func (p *Packet) GetAll(code byte) [][]byte {
	var out [][]byte
	for _, o := range p.Options {
		if o.Code == code {
			out = append(out, o.Data)
		}
	}
	return out
}

func (p *Packet) Set(code byte, data []byte) {
	dup := append([]byte(nil), data...)
	for i, o := range p.Options {
		if o.Code == code {
			p.Options[i].Data = dup
			return
		}
	}
	p.Options = append(p.Options, Option{Code: code, Data: dup})
}

func (p *Packet) Add(code byte, data []byte) {
	p.Options = append(p.Options, Option{Code: code, Data: append([]byte(nil), data...)})
}

// Append adds a prepared option.
func (p *Packet) Append(o Option) {
	p.Add(o.Code, o.Data)
}

// RelayAgentBlobs returns option 82 payloads in wire order, copied.
func (p *Packet) RelayAgentBlobs() [][]byte {
	all := p.GetAll(OptRelayAgent)
	out := make([][]byte, len(all))
	for i, d := range all {
		out[i] = append([]byte(nil), d...)
	}
	return out
}

func (p *Packet) Broadcast() bool {
	return p.Flags&flagBroadcast != 0
}

func (p *Packet) SetBroadcast(v bool) {
	if v {
		p.Flags |= flagBroadcast
	} else {
		p.Flags &^= flagBroadcast
	}
}

// Relayed reports a non-zero giaddr (RFC 2131 relay path).
func (p *Packet) Relayed() bool {
	return p.GIAddr.IsValid() && !p.GIAddr.IsUnspecified()
}

// MAC returns the client hardware address as aa:bb:cc:dd:ee:ff.
func (p *Packet) MAC() string {
	n := int(p.HLen)
	if n <= 0 || n > len(p.CHAddr) {
		n = len(p.CHAddr)
		if n > 6 {
			n = 6
		}
	}
	if n == 0 {
		return ""
	}
	return net.HardwareAddr(p.CHAddr[:n]).String()
}

func (p *Packet) ClientID() string {
	d, ok := p.Get(OptClientID)
	if !ok || len(d) == 0 {
		return ""
	}
	return hex.EncodeToString(d)
}

func (p *Packet) Hostname() string {
	if fqdn, ok := p.ClientFQDN(); ok {
		if fqdn.Flags&FQDNNoUpdate != 0 {
			return ""
		}
		return fqdn.Name
	}
	d, ok := p.Get(OptHostname)
	if !ok {
		return ""
	}
	return string(d)
}

func (p *Packet) VendorClass() string {
	d, ok := p.Get(OptVendorClass)
	if !ok {
		return ""
	}
	return string(d)
}

func (p *Packet) RequestedIP() (netip.Addr, bool) {
	d, ok := p.Get(OptRequestedIP)
	if !ok || len(d) != 4 {
		return netip.Addr{}, false
	}
	return addr4(d), true
}

func (p *Packet) ServerID() (netip.Addr, bool) {
	d, ok := p.Get(OptServerID)
	if !ok || len(d) != 4 {
		return netip.Addr{}, false
	}
	return addr4(d), true
}

func (p *Packet) RequestedLease() (uint32, bool) {
	d, ok := p.Get(OptLeaseTime)
	if !ok || len(d) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(d), true
}

func addr4(b []byte) netip.Addr {
	var a [4]byte
	copy(a[:], b)
	return netip.AddrFrom4(a)
}

func putAddr(dst []byte, a netip.Addr) {
	if !a.IsValid() || !a.Is4() {
		return
	}
	b := a.As4()
	copy(dst, b[:])
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func putCString(dst []byte, s string) {
	if len(s) >= len(dst) {
		s = s[:len(dst)-1]
	}
	copy(dst, s)
}

func parseOptions(b []byte) ([]Option, error) {
	var out []Option
	for i := 0; i < len(b); {
		code := b[i]
		if code == OptPad {
			i++
			continue
		}
		if code == OptEnd {
			break
		}
		if i+1 >= len(b) {
			return nil, fmt.Errorf("dhcp: truncated option %d", code)
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return nil, fmt.Errorf("dhcp: truncated option %d length %d", code, n)
		}
		out = append(out, Option{Code: code, Data: append([]byte(nil), b[i+2:i+2+n]...)})
		i += 2 + n
	}
	return out, nil
}
