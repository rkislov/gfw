// Package netconfig describes the static, explicitly owned part of the network.
package netconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var Name = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$`)

type Link struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Parent    string   `json:"parent"`
	VLAN      int      `json:"vlan"`
	Members   []string `json:"members"`
	BondMode  string   `json:"bond_mode"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
	Adopt     bool     `json:"adopt"`
}
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}
type Config struct {
	Interfaces []Link  `json:"interfaces"`
	Routes     []Route `json:"routes"`
}

func Empty() Config { return Config{Interfaces: []Link{}, Routes: []Route{}} }

func Canonical(c Config) Config {
	if c.Interfaces != nil {
		c.Interfaces = append([]Link{}, c.Interfaces...)
	}
	if c.Routes != nil {
		c.Routes = append([]Route{}, c.Routes...)
	}
	for i := range c.Interfaces {
		l := &c.Interfaces[i]
		l.Members = append([]string{}, l.Members...)
		l.Addresses = append([]string{}, l.Addresses...)
		for j, a := range l.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				l.Addresses[j] = p.String()
			}
		}
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		if p, err := netip.ParsePrefix(r.Destination); err == nil {
			r.Destination = p.String()
		}
		if a, err := netip.ParseAddr(r.Gateway); err == nil {
			r.Gateway = a.String()
		}
	}
	return c
}
func (c Config) Map() map[string]Link {
	out := map[string]Link{}
	for _, l := range c.Interfaces {
		out[l.Name] = l
	}
	return out
}
func Validate(c Config) error {
	if c.Interfaces == nil || c.Routes == nil {
		return errors.New("interfaces и routes должны быть массивами")
	}
	if len(c.Interfaces) > 128 || len(c.Routes) > 1024 {
		return errors.New("не более 128 интерфейсов и 1024 маршрутов")
	}
	links := c.Map()
	if len(links) != len(c.Interfaces) {
		return errors.New("имена интерфейсов повторяются")
	}
	members := map[string]string{}
	vlans := map[string]bool{}
	ips := map[netip.Addr]string{}
	for _, l := range c.Interfaces {
		if !Name.MatchString(l.Name) || l.Name == "lo" || l.Name == "default" {
			return fmt.Errorf("недопустимое имя интерфейса %q", l.Name)
		}
		if l.Type != "physical" && l.Type != "vlan" && l.Type != "bridge" && l.Type != "bond" {
			return fmt.Errorf("%s: неизвестный тип", l.Name)
		}
		if l.MTU < 576 || l.MTU > 9216 {
			return fmt.Errorf("%s: MTU должен быть 576–9216", l.Name)
		}
		if len(l.Addresses) > 32 || len(l.Members) > 32 {
			return errors.New("слишком много адресов или портов")
		}
		if l.Type == "vlan" {
			if !Name.MatchString(l.Parent) || l.Parent == l.Name || l.VLAN < 1 || l.VLAN > 4094 {
				return fmt.Errorf("%s: нужны родитель и VLAN ID 1–4094", l.Name)
			}
			key := fmt.Sprintf("%s/%d", l.Parent, l.VLAN)
			if vlans[key] {
				return errors.New("повтор VLAN ID на одном родителе")
			}
			vlans[key] = true
			if p, ok := links[l.Parent]; ok && l.MTU > p.MTU {
				return errors.New("MTU VLAN больше родительского")
			}
		} else if l.Parent != "" || l.VLAN != 0 {
			return errors.New("родитель и VLAN ID допустимы только для VLAN")
		}
		if l.Type == "bond" {
			if l.BondMode != "active-backup" && l.BondMode != "802.3ad" {
				return errors.New("bond: допустимы active-backup и 802.3ad")
			}
			if len(l.Members) < 2 {
				return errors.New("bond требует минимум два порта")
			}
		} else if l.BondMode != "" {
			return errors.New("режим агрегации допустим только для bond")
		}
		if l.Type != "bridge" && l.Type != "bond" && len(l.Members) != 0 {
			return errors.New("порты допустимы только для bridge/bond")
		}
		for _, n := range l.Members {
			p, ok := links[n]
			if !ok || n == l.Name {
				return fmt.Errorf("%s: порт %s должен быть отдельным управляемым интерфейсом", l.Name, n)
			}
			if members[n] != "" {
				return fmt.Errorf("%s уже включён в %s", n, members[n])
			}
			members[n] = l.Name
			if (l.Up && !p.Up) || len(p.Addresses) > 0 || p.MTU != l.MTU {
				return fmt.Errorf("%s: порт должен быть включён, без IP, с MTU как у %s", n, l.Name)
			}
			if l.Type == "bond" && p.Type != "physical" {
				return errors.New("портами bond могут быть только физические интерфейсы")
			}
		}
		for _, a := range l.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().Is4In6() {
				return fmt.Errorf("%s: недопустимый статический IP/CIDR %q", l.Name, a)
			}
			if p.Addr().Is6() && l.MTU < 1280 {
				return errors.New("IPv6 требует MTU не меньше 1280")
			}
			if previous := ips[p.Addr()]; previous != "" {
				return fmt.Errorf("IP %s повторяется на %s и %s", p.Addr(), previous, l.Name)
			}
			ips[p.Addr()] = l.Name
		}
	}
	if _, err := Order(c.Interfaces); err != nil {
		return err
	}
	for i, a := range c.Interfaces {
		for _, b := range c.Interfaces[i+1:] {
			for _, x := range a.Addresses {
				p, _ := netip.ParsePrefix(x)
				for _, y := range b.Addresses {
					q, _ := netip.ParsePrefix(y)
					if p.Overlaps(q) {
						return fmt.Errorf("подсети %s и %s пересекаются", a.Name, b.Name)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range c.Routes {
		l, ok := links[r.Interface]
		if !ok || !l.Up || members[r.Interface] != "" {
			return errors.New("маршрут должен ссылаться на включённый интерфейс с IP, не порт моста/bond")
		}
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil || p != p.Masked() || p.Addr().Is4In6() {
			return errors.New("назначение маршрута должно быть адресом сети IP/CIDR")
		}
		if r.Metric < 1 || r.Metric > 65535 {
			return errors.New("метрика должна быть 1–65535")
		}
		if r.Gateway != "" {
			g, err := netip.ParseAddr(r.Gateway)
			if err != nil || g.Is4() != p.Addr().Is4() || g.IsUnspecified() || g.IsMulticast() || g.IsLoopback() {
				return errors.New("недопустимый шлюз или семейство IP")
			}
			// IPv6 link-local gateways are tied to the explicitly selected
			// interface; they need not belong to its global address prefix.
			reachable := g.Is6() && g.IsLinkLocalUnicast()
			for _, a := range l.Addresses {
				ap, _ := netip.ParsePrefix(a)
				if ap.Contains(g) && ap.Addr() != g {
					reachable = true
				}
			}
			if !reachable {
				return errors.New("шлюз должен находиться в подключённой подсети интерфейса")
			}
		}
		key := fmt.Sprintf("%s/%d", r.Destination, r.Metric)
		if seen[key] {
			return errors.New("повтор назначения и метрики маршрута")
		}
		seen[key] = true
	}
	return nil
}
func Order(links []Link) ([]Link, error) {
	index := map[string]Link{}
	for _, l := range links {
		index[l.Name] = l
	}
	visiting := map[string]bool{}
	done := map[string]bool{}
	out := []Link{}
	var walk func(string) error
	walk = func(name string) error {
		l, ok := index[name]
		if !ok || done[name] {
			return nil
		}
		if visiting[name] {
			return errors.New("циклическая зависимость интерфейсов")
		}
		visiting[name] = true
		deps := append([]string{}, l.Members...)
		if l.Parent != "" {
			deps = append(deps, l.Parent)
		}
		for _, d := range deps {
			if err := walk(d); err != nil {
				return err
			}
		}
		visiting[name] = false
		done[name] = true
		out = append(out, l)
		return nil
	}
	names := []string{}
	for n := range index {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := walk(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Render emits only typed values: no shell fragments, hooks or arbitrary options.
func Render(c Config) map[string]map[string]string {
	c = Canonical(c)
	out := map[string]map[string]string{}
	for _, l := range c.Interfaces {
		typ := map[string]string{"physical": "eth", "vlan": "vlan", "bridge": "bri", "bond": "bond"}[l.Type]
		on := "yes"
		if !l.Up {
			on = "no"
		}
		options := fmt.Sprintf("# Managed by GFW\nTYPE=%s\nBOOTPROTO=static\nONBOOT=%s\nDISABLED=no\nNM_CONTROLLED=no\nUSE_IFPLUGD=no\nUSE_HOTPLUG=no\nCONFIG_WIRELESS=no\nCONFIG_IPV4=yes\nCONFIG_IPV6=yes\nMTU=%d\n", typ, on, l.MTU)
		if l.Type == "vlan" {
			options += fmt.Sprintf("HOST='%s'\nVID=%d\n", l.Parent, l.VLAN)
		}
		if l.Type == "bridge" {
			options += fmt.Sprintf("HOST='%s'\nBRIDGE_OPTIONS='stp_state 0'\n", strings.Join(l.Members, " "))
		}
		if l.Type == "bond" {
			mode := 1
			if l.BondMode == "802.3ad" {
				mode = 4
			}
			options += fmt.Sprintf("HOST='%s'\nBONDMODE=%d\nBONDOPTIONS='miimon=100'\n", strings.Join(l.Members, " "), mode)
		}
		files := map[string]string{"options": options, "ipv4address": "", "ipv6address": "", "ipv4route": "", "ipv6route": "", "sysctl.conf": "accept_ra=0\nautoconf=0\n", ".gfw-owned": "gfw-network-v1\n"}
		for _, a := range l.Addresses {
			p, _ := netip.ParsePrefix(a)
			key := "ipv4address"
			if p.Addr().Is6() {
				key = "ipv6address"
			}
			files[key] += a + "\n"
		}
		for _, r := range c.Routes {
			if r.Interface != l.Name {
				continue
			}
			p, _ := netip.ParsePrefix(r.Destination)
			key := "ipv4route"
			if p.Addr().Is6() {
				key = "ipv6route"
			}
			line := r.Destination
			if r.Gateway != "" {
				line += " via " + r.Gateway
			}
			files[key] += fmt.Sprintf("%s dev %s metric %d proto 186\n", line, r.Interface, r.Metric)
		}
		out[l.Name] = files
	}
	return out
}
