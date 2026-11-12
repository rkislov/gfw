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
	"fmt"
	"regexp"
	"strconv"
)

// Parser extracts a VLAN id from a circuit id using a named regular expression.
type Parser struct {
	Name      string
	Pattern   string
	VLANGroup string
	re        *regexp.Regexp
	groupIdx  int
}

// BuiltinParsers are the vendor circuit-id parsers shipped with GoDHCP.
func BuiltinParsers() []Parser {
	specs := []struct {
		name, pattern, group string
	}{
		{"eltex", `^(?:[^\x00-\x20]+ )?eth (?P<port>\d+(?:/\d+){1,2}):(?P<vlan>\d+)(?:[\x00-\x1f])?$`, "vlan"},
		{"cisco", `^(?P<port>[^:]+):vlan(?P<vlan>\d+)$`, "vlan"},
		{"huawei", `^slot=(?P<slot>\d+);subslot=(?P<sub>\d+);(?P<port>[^;]+);vlanid=(?P<vlan>\d+)$`, "vlan"},
		{"extreme", `^(?P<slot>\d+):(?P<port>\d+):(?P<vlan>\d+)$`, "vlan"},
		{"juniper", `^(?P<iface>(?:ge|xe|et|ae|irb)[^:]*):vlan-id(?P<vlan>\d+)$`, "vlan"},
		{"mikrotik", `^(?P<iface>[^:]+):(?P<vlan>\d+)$`, "vlan"},
		{"aruba", `^(?:port(?P<port>\d+):)?vlan(?P<vlan>\d+)$`, "vlan"},
		{"hp", `^(?P<port>[^:]+):(?P<vlan>\d+)$`, "vlan"},
		{"brocade", `^(?P<port>.+)/vlan(?P<vlan>\d+)$`, "vlan"},
		{"qtech", `^vlan(?P<vlan>\d+)\+Ethernet(?P<port>\d+/\d+/\d+)$`, "vlan"},
		{"unifi", `^vlan(?P<vlan>\d+)$`, "vlan"},
	}
	out := make([]Parser, 0, len(specs))
	for _, s := range specs {
		p, err := Compile(s.name, s.pattern, s.group)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Compile checks the expression and resolves the VLAN capture group.
func Compile(name, pattern, vlanGroup string) (Parser, error) {
	if name == "" {
		return Parser{}, fmt.Errorf("relay: parser name is empty")
	}
	if vlanGroup == "" {
		vlanGroup = "vlan"
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Parser{}, fmt.Errorf("relay: parser %s: %w", name, err)
	}
	idx := -1
	for i, n := range re.SubexpNames() {
		if n == vlanGroup {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Parser{}, fmt.Errorf("relay: parser %s: group %q not found", name, vlanGroup)
	}
	return Parser{Name: name, Pattern: pattern, VLANGroup: vlanGroup, re: re, groupIdx: idx}, nil
}

// Parse returns the VLAN id and named groups when the circuit id matches.
func (p Parser) Parse(circuitID string) (int, map[string]string, bool) {
	if p.re == nil || circuitID == "" {
		return 0, nil, false
	}
	m := p.re.FindStringSubmatch(circuitID)
	if m == nil {
		return 0, nil, false
	}
	if p.groupIdx >= len(m) {
		return 0, nil, false
	}
	vlan, err := strconv.Atoi(m[p.groupIdx])
	if err != nil || vlan < 1 || vlan > 4094 {
		return 0, nil, false
	}
	fields := make(map[string]string, len(m))
	for i, name := range p.re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		fields[name] = m[i]
	}
	return vlan, fields, true
}

// MergeParsers overlays configured parsers on top of built-ins. Same name replaces.
func MergeParsers(configured []Parser) []Parser {
	byName := map[string]Parser{}
	var order []string
	add := func(p Parser) {
		if _, ok := byName[p.Name]; !ok {
			order = append(order, p.Name)
		}
		byName[p.Name] = p
	}
	for _, p := range BuiltinParsers() {
		add(p)
	}
	for _, p := range configured {
		add(p)
	}
	out := make([]Parser, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// MatchVLAN tries parsers in order, or only the explicitly selected parser.
func MatchVLAN(parsers []Parser, circuitID, onlyName string) (vlan int, parser string, fields map[string]string, ok bool) {
	if circuitID == "" {
		return 0, "", nil, false
	}
	try := func(p Parser) (int, string, map[string]string, bool) {
		v, f, matched := p.Parse(circuitID)
		if !matched {
			return 0, "", nil, false
		}
		return v, p.Name, f, true
	}
	if onlyName != "" {
		for _, p := range parsers {
			if p.Name == onlyName {
				if v, name, f, matched := try(p); matched {
					return v, name, f, true
				}
			}
		}
		return 0, "", nil, false
	}
	for _, p := range parsers {
		if onlyName != "" && p.Name == onlyName {
			continue
		}
		if v, name, f, matched := try(p); matched {
			return v, name, f, true
		}
	}
	return 0, "", nil, false
}
