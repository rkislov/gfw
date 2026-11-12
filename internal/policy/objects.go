package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Zone struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Interfaces []string `json:"interfaces"`
}
type AddressGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Family   string   `json:"family"`
	Networks []string `json:"networks"`
}
type ServiceGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}
type NAT struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Enabled           bool   `json:"enabled"`
	SourceZone        string `json:"source_zone"`
	DestinationZone   string `json:"destination_zone"`
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	Protocol          string `json:"protocol"`
	DestinationPort   int    `json:"destination_port"`
	TranslatedAddress string `json:"translated_address"`
	TranslatedPort    int    `json:"translated_port"`
	AllowForward      bool   `json:"allow_forward"`
	Hairpin           bool   `json:"hairpin"`
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func title(id, name string) error {
	if !identifier.MatchString(id) || len(name) == 0 || len(name) > 200 {
		return errors.New("объекту нужны ID и название длиной до 200 байт")
	}
	return nil
}
func portRange(s string) (int, int, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("порт: число или диапазон 8000-8100")
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil || a < 1 || a > 65535 {
		return 0, 0, errors.New("порт должен быть 1–65535")
	}
	b := a
	if len(parts) == 2 {
		b, err = strconv.Atoi(parts[1])
		if err != nil || b < a || b > 65535 {
			return 0, 0, errors.New("недопустимый диапазон портов")
		}
	}
	return a, b, nil
}
func servicePorts(g ServiceGroup) []string {
	type pair struct{ a, b int }
	xs := []pair{}
	for _, s := range g.Ports {
		a, b, _ := portRange(s)
		xs = append(xs, pair{a, b})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].a < xs[j].a })
	merged := []pair{}
	for _, x := range xs {
		if len(merged) > 0 && x.a <= merged[len(merged)-1].b+1 {
			if x.b > merged[len(merged)-1].b {
				merged[len(merged)-1].b = x.b
			}
		} else {
			merged = append(merged, x)
		}
	}
	out := []string{}
	for _, x := range merged {
		s := strconv.Itoa(x.a)
		if x.b != x.a {
			s += "-" + strconv.Itoa(x.b)
		}
		out = append(out, s)
	}
	return out
}
func validPrefix(s, family string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil || p != p.Masked() || p.Addr().Is4In6() {
		return errors.New("укажите сеть CIDR без битов хоста")
	}
	if (p.Addr().Is4() && family != "ipv4") || (!p.Addr().Is4() && family != "ipv6") {
		return errors.New("адрес не соответствует семейству IP")
	}
	return nil
}
func groupFamily(c Config, r Rule) (string, error) {
	f := r.Family
	for _, id := range []string{r.SourceGroup, r.DestinationGroup} {
		if id == "" {
			continue
		}
		found := false
		for _, g := range c.AddressGroups {
			if g.ID == id {
				found = true
				if f != "any" && f != g.Family {
					return "", errors.New("группа адресов не соответствует семейству правила")
				}
				f = g.Family
			}
		}
		if !found {
			return "", fmt.Errorf("группа адресов %s не найдена", id)
		}
	}
	return f, nil
}
func validateObjects(c Config) error {
	if len(c.Zones) > 64 || len(c.AddressGroups) > 512 || len(c.ServiceGroups) > 512 || len(c.NAT) > 1024 {
		return errors.New("превышен лимит зон, групп или NAT")
	}
	ids := map[string]bool{}
	claim := func(id, name string) error {
		if err := title(id, name); err != nil {
			return err
		}
		if ids[id] {
			return errors.New("ID объектов должны быть уникальны")
		}
		ids[id] = true
		return nil
	}
	assigned := map[string]string{}
	zones := map[string]Zone{}
	for _, z := range c.Zones {
		if err := claim(z.ID, z.Name); err != nil {
			return err
		}
		if z.Kind != "lan" && z.Kind != "wan" && z.Kind != "dmz" && z.Kind != "vpn" && z.Kind != "management" && z.Kind != "custom" {
			return errors.New("неизвестный тип зоны")
		}
		if len(z.Interfaces) > 64 {
			return errors.New("слишком много интерфейсов в зоне")
		}
		for _, n := range z.Interfaces {
			if !interfaceName.MatchString(n) || n == "lo" {
				return errors.New("недопустимый интерфейс зоны")
			}
			if other := assigned[n]; other != "" {
				return fmt.Errorf("интерфейс %s уже назначен зоне %s", n, other)
			}
			assigned[n] = z.Name
		}
		zones[z.ID] = z
	}
	for _, g := range c.AddressGroups {
		if err := claim(g.ID, g.Name); err != nil {
			return err
		}
		if g.Family != "ipv4" && g.Family != "ipv6" {
			return errors.New("для группы адресов выберите IPv4 или IPv6")
		}
		if len(g.Networks) < 1 || len(g.Networks) > 10000 {
			return errors.New("группа должна содержать 1–10000 сетей")
		}
		for _, s := range g.Networks {
			if err := validPrefix(s, g.Family); err != nil {
				return fmt.Errorf("%s: %w", g.Name, err)
			}
		}
	}
	services := map[string]ServiceGroup{}
	for _, g := range c.ServiceGroups {
		if err := claim(g.ID, g.Name); err != nil {
			return err
		}
		if g.Protocol != "tcp" && g.Protocol != "udp" && g.Protocol != "tcp_udp" {
			return errors.New("сервис: выберите TCP, UDP или TCP+UDP")
		}
		if len(g.Ports) < 1 || len(g.Ports) > 128 {
			return errors.New("сервис должен содержать 1–128 портов/диапазонов")
		}
		for _, p := range g.Ports {
			if _, _, err := portRange(p); err != nil {
				return err
			}
		}
		services[g.ID] = g
	}
	checkZone := func(id string, enabled bool) error {
		if id == "" {
			return nil
		}
		z, ok := zones[id]
		if !ok {
			return fmt.Errorf("зона %s используется, но не найдена", id)
		}
		if enabled && len(z.Interfaces) == 0 {
			return fmt.Errorf("назначьте интерфейс зоне %s", z.Name)
		}
		return nil
	}
	for _, r := range c.Rules {
		if err := checkZone(r.SourceZone, r.Enabled); err != nil {
			return err
		}
		if err := checkZone(r.DestinationZone, r.Enabled); err != nil {
			return err
		}
		if r.Chain == "input" && r.DestinationZone != "" {
			return errors.New("для трафика к устройству выбирается только зона источника")
		}
		if r.Chain == "output" && r.SourceZone != "" {
			return errors.New("для трафика от устройства выбирается только зона назначения")
		}
		if r.SourceGroup != "" && r.Source != "" || r.DestinationGroup != "" && r.Destination != "" {
			return errors.New("выберите прямой CIDR или группу адресов, не оба сразу")
		}
		if _, err := groupFamily(c, r); err != nil {
			return err
		}
		if r.Service != "" {
			if _, ok := services[r.Service]; !ok {
				return fmt.Errorf("сервис %s используется, но не найден", r.Service)
			}
			if r.Protocol != "any" || r.DestinationPort != 0 {
				return errors.New("при выборе сервиса протокол и порты берутся из группы")
			}
		}
	}
	natKeys := map[string]bool{}
	for _, n := range c.NAT {
		if err := claim(n.ID, n.Name); err != nil {
			return err
		}
		if n.Type != "dnat" && n.Type != "snat" && n.Type != "masquerade" && n.Type != "no_snat" {
			return errors.New("неизвестный вид NAT")
		}
		if n.SourceZone == "" || n.DestinationZone == "" {
			return errors.New("для NAT укажите входную и выходную зоны")
		}
		if err := checkZone(n.SourceZone, n.Enabled); err != nil {
			return err
		}
		if err := checkZone(n.DestinationZone, n.Enabled); err != nil {
			return err
		}
		for _, p := range []string{n.Source, n.Destination} {
			if p != "" {
				if err := validPrefix(p, "ipv4"); err != nil {
					return fmt.Errorf("NAT поддерживает только IPv4: %w", err)
				}
			}
		}
		if n.Protocol != "any" && n.Protocol != "tcp" && n.Protocol != "udp" {
			return errors.New("протокол NAT: TCP, UDP или любой")
		}
		if n.DestinationPort < 0 || n.DestinationPort > 65535 || n.TranslatedPort < 0 || n.TranslatedPort > 65535 {
			return errors.New("порт NAT должен быть 1–65535 или пустым")
		}
		if n.DestinationPort != 0 && n.Protocol == "any" {
			return errors.New("для порта NAT нужен TCP или UDP")
		}
		if n.Type == "dnat" || n.Type == "snat" {
			a, err := netip.ParseAddr(n.TranslatedAddress)
			if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.String() == "255.255.255.255" {
				return errors.New("укажите одиночный IPv4-адрес преобразования")
			}
		} else if n.TranslatedAddress != "" {
			return errors.New("адрес преобразования не применяется к masquerade/исключению")
		}
		if n.Type == "dnat" {
			if n.Protocol == "any" || n.DestinationPort == 0 {
				return errors.New("для проброса нужен TCP/UDP и внешний порт")
			}
			if n.TranslatedPort == 0 {
				return errors.New("для проброса нужен внутренний порт")
			}
			if n.AllowForward && !c.Stateful {
				return errors.New("автоматическое разрешение проброса требует stateful-режима")
			}
			if n.Hairpin {
				p, err := netip.ParsePrefix(n.Destination)
				if err != nil || p.Bits() != 32 || !n.AllowForward || n.SourceZone == n.DestinationZone {
					return errors.New("hairpin требует внешний IP/32, разные зоны и явное разрешение проброса")
				}
			}
			key := fmt.Sprintf("%s/%s/%s/%d", n.SourceZone, n.Destination, n.Protocol, n.DestinationPort)
			if natKeys[key] {
				return errors.New("повторяющийся проброс порта в одной зоне")
			}
			natKeys[key] = true
		} else if n.TranslatedPort != 0 || n.AllowForward || n.Hairpin {
			return errors.New("внутренний порт, разрешение и hairpin доступны только для проброса")
		}
	}
	return nil
}

// Canonical supplies optional collections for old configurations without
// enabling new stateful behavior or changing already-saved rule semantics.
func Canonical(c Config) Config {
	c.Flowtable = canonicalFlow(c.Flowtable)
	c.Zones = append([]Zone{}, c.Zones...)
	for i := range c.Zones {
		c.Zones[i].Interfaces = append([]string{}, c.Zones[i].Interfaces...)
	}
	c.AddressGroups = append([]AddressGroup{}, c.AddressGroups...)
	for i := range c.AddressGroups {
		g := &c.AddressGroups[i]
		g.Networks = append([]string{}, g.Networks...)
		for j, n := range g.Networks {
			if a, err := netip.ParseAddr(n); err == nil {
				bits := 128
				if a.Is4() {
					bits = 32
				}
				g.Networks[j] = netip.PrefixFrom(a, bits).String()
			} else if p, err := netip.ParsePrefix(n); err == nil {
				g.Networks[j] = p.String()
			}
		}
	}
	if c.Zones == nil {
		c.Zones = []Zone{}
	}
	if c.AddressGroups == nil {
		c.AddressGroups = []AddressGroup{}
	}
	if c.ServiceGroups == nil {
		c.ServiceGroups = []ServiceGroup{}
	}
	if c.NAT == nil {
		c.NAT = []NAT{}
	}
	return c
}

func SafetyCheck(c Config, s Safety) error {
	for _, z := range c.Zones {
		for _, n := range z.Interfaces {
			if n == s.LANInterface && z.Kind != "lan" && z.Kind != "management" {
				return errors.New("защищённый LAN можно назначить только зоне LAN или управления")
			}
		}
	}
	for _, n := range c.NAT {
		if !n.Enabled || n.Type != "dnat" || n.Protocol != "tcp" || n.DestinationPort != s.ManagementPort {
			continue
		}
		for _, z := range c.Zones {
			if z.ID != n.SourceZone && !(n.Hairpin && z.ID == n.DestinationZone) {
				continue
			}
			for _, name := range z.Interfaces {
				if name == s.LANInterface {
					return errors.New("проброс не может перехватывать порт панели на защищённом LAN")
				}
			}
		}
	}
	return nil
}
