// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dhcp

import "strings"

const OptClientFQDN byte = 81
const (
	FQDNServer   byte = 1
	FQDNOverride byte = 2
	FQDNEncoded  byte = 4
	FQDNNoUpdate byte = 8
)

type ClientFQDN struct {
	Flags byte
	Name  string
}

func (p *Packet) ClientFQDN() (ClientFQDN, bool) {
	raw, ok := p.Get(OptClientFQDN)
	if !ok || len(raw) < 3 {
		return ClientFQDN{}, false
	}
	result := ClientFQDN{Flags: raw[0]}
	if raw[0]&FQDNEncoded == 0 {
		result.Name = string(raw[3:])
		if strings.ContainsRune(result.Name, 0) {
			return ClientFQDN{}, false
		}
		return result, true
	}
	data := raw[3:]
	labels := []string{}
	for len(data) > 0 {
		n := int(data[0])
		data = data[1:]
		if n == 0 {
			if len(data) != 0 {
				return ClientFQDN{}, false
			}
			result.Name = strings.Join(labels, ".")
			if len(labels) > 0 {
				result.Name += "."
			}
			return result, true
		}
		if n > 63 || n > len(data) {
			return ClientFQDN{}, false
		} // Includes compression pointers.
		for _, ch := range data[:n] {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return ClientFQDN{}, false
			}
		}
		labels = append(labels, string(data[:n]))
		data = data[n:]
	}
	result.Name = strings.Join(labels, ".")
	return result, true // Partial DNS name.
}
func FQDNOption(flags byte, name string) Option {
	raw := []byte{flags, 255, 255}
	if flags&FQDNEncoded == 0 {
		return Option{Code: OptClientFQDN, Data: append(raw, []byte(name)...)}
	}
	full := strings.HasSuffix(name, ".")
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 || label == "" {
				return Option{Code: OptClientFQDN, Data: raw}
			}
			raw = append(raw, byte(len(label)))
			raw = append(raw, []byte(label)...)
		}
	}
	if full {
		raw = append(raw, 0)
	}
	return Option{Code: OptClientFQDN, Data: raw}
}
