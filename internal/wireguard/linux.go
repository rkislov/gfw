//go:build linux

package wireguard

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"time"
)

const routeProtocol = 242
const ownerPrefix = "gfw:wireguard:"

type Linux struct {
	Vault *Vault
	LAN   string
}

func (l *Linux) GenerateKey(kind string) (KeyInfo, error)     { return l.Vault.Generate(kind) }
func (l *Linux) Export(c Config, t, p string) (string, error) { return l.Vault.ClientProfile(c, t, p) }
func ownerGroup(t Tunnel) uint32 {
	sum := sha256.Sum256([]byte(t.ID))
	return binary.BigEndian.Uint32(sum[:4]) | 0x80000000
}
func claimable(link netlink.Link, t Tunnel) bool {
	return link.Type() == "wireguard" && link.Attrs().Group == ownerGroup(t) && (link.Attrs().Alias == ownerPrefix+t.ID || link.Attrs().Alias == "")
}
func owned(link netlink.Link, t Tunnel) bool {
	return claimable(link, t) && link.Attrs().Alias == ownerPrefix+t.ID
}
func network(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
func asPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a, bits), true
}
func routeKey(n *net.IPNet) string {
	p, ok := asPrefix(n)
	if !ok {
		return "default"
	}
	return p.Masked().String()
}
func (l *Linux) guardLink(link netlink.Link) error {
	if link.Attrs().Name == l.LAN || link.Attrs().MasterIndex != 0 {
		return errors.New("WireGuard не меняет защищённый LAN и включённые в другие устройства интерфейсы")
	}
	links, e := netlink.LinkList()
	if e != nil {
		return e
	}
	for _, child := range links {
		if child.Attrs().ParentIndex == link.Attrs().Index || child.Attrs().MasterIndex == link.Attrs().Index {
			return errors.New("WireGuard-интерфейс используется внешним сетевым устройством")
		}
	}
	routes, e := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if e != nil {
		return e
	}
	for _, r := range routes {
		if r.Table != unix.RT_TABLE_MAIN && r.Table != 0 {
			if r.Table == unix.RT_TABLE_LOCAL && r.Protocol == unix.RTPROT_KERNEL {
				continue
			}
			return errors.New("на WireGuard-интерфейсе есть чужие таблицы маршрутизации")
		}
		if r.Protocol != unix.RTPROT_KERNEL && r.Protocol != routeProtocol {
			return errors.New("на WireGuard-интерфейсе есть чужие маршруты; изменение запрещено")
		}
	}
	return nil
}
func (l *Linux) Prepare(c, old Config) (Plan, error) {
	p := Preview(c)
	if e := Validate(c); e != nil {
		return p, e
	}
	if e := l.Vault.Validate(c); e != nil {
		return p, e
	}
	if e := l.Verify(old); e != nil {
		return p, fmt.Errorf("текущее состояние WireGuard отличается от подтверждённого: %w", e)
	}
	active, previous := Active(c), Active(old)
	for _, t := range c.Tunnels {
		if t.Name == l.LAN {
			return p, errors.New("имя туннеля совпадает с защищённым LAN")
		}
		link, e := netlink.LinkByName(t.Name)
		if e == nil {
			known, ok := previous[t.Name]
			if !ok || !owned(link, known) || known.ID != t.ID {
				return p, errors.New("имя WireGuard занято чужим интерфейсом")
			}
			if e = l.guardLink(link); e != nil {
				return p, e
			}
		} else {
			var missing netlink.LinkNotFoundError
			if !errors.As(e, &missing) {
				return p, e
			}
		}
	}
	links, e := netlink.LinkList()
	if e != nil {
		return p, e
	}
	for _, link := range links {
		if _, ok := previous[link.Attrs().Name]; ok {
			continue
		}
		foreign, e := netlink.AddrList(link, netlink.FAMILY_ALL)
		if e != nil {
			return p, e
		}
		for _, a := range foreign {
			n, ok := asPrefix(a.IPNet)
			if !ok || n.Addr().IsLoopback() || n.Addr().IsLinkLocalUnicast() {
				continue
			}
			for _, t := range active {
				for _, s := range t.Addresses {
					own, _ := netip.ParsePrefix(s)
					if own.Overlaps(n) {
						return p, fmt.Errorf("адреса %s пересекают сеть интерфейса %s", t.Name, link.Attrs().Name)
					}
				}
				for _, r := range Routes(t) {
					if r.Overlaps(n) {
						return p, fmt.Errorf("маршрут %s пересекает сеть интерфейса %s", r, link.Attrs().Name)
					}
				}
			}
		}
	}
	routes, e := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if e != nil {
		return p, e
	}
	for _, r := range routes {
		if _, ok := findLinkIndex(previous, r.LinkIndex); ok {
			continue
		}
		n, ok := asPrefix(r.Dst)
		if !ok || n.Bits() == 0 {
			continue
		}
		for _, t := range active {
			for _, want := range Routes(t) {
				if n.Overlaps(want) {
					return p, fmt.Errorf("маршрут %s пересекается с существующим маршрутом %s", want, n)
				}
			}
		}
	}
	client, e := wgctrl.New()
	if e != nil {
		return p, e
	}
	defer client.Close()
	if _, e = client.Devices(); e != nil {
		return p, errors.New("WireGuard netlink недоступен в ядре")
	}
	p.CanApply = true
	return p, nil
}
func findLinkIndex(ts map[string]Tunnel, index int) (Tunnel, bool) {
	for _, t := range ts {
		if link, e := netlink.LinkByName(t.Name); e == nil && link.Attrs().Index == index {
			return t, true
		}
	}
	return Tunnel{}, false
}
func (l *Linux) Activate(c, old Config) error {
	if e := Validate(c); e != nil {
		return e
	}
	if e := l.Vault.Validate(c); e != nil {
		return e
	}
	scope := map[string][]Tunnel{}
	for _, x := range []Config{old, c} {
		for _, t := range x.Tunnels {
			scope[t.Name] = append(scope[t.Name], t)
		}
	}
	// Check the entire mutation scope before deleting any link. No adoption.
	for name, ts := range scope {
		link, e := netlink.LinkByName(name)
		if e != nil {
			var missing netlink.LinkNotFoundError
			if errors.As(e, &missing) {
				continue
			}
			return e
		}
		allowed := false
		for _, t := range ts {
			if claimable(link, t) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("интерфейс %s не принадлежит GFW WireGuard", name)
		}
		if e = l.guardLink(link); e != nil {
			return e
		}
	}
	names := []string{}
	for n := range scope {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		link, e := netlink.LinkByName(n)
		if e == nil {
			if e = netlink.LinkDel(link); e != nil {
				return e
			}
		}
	}
	if len(Active(c)) == 0 {
		return nil
	}
	client, e := wgctrl.New()
	if e != nil {
		return e
	}
	defer client.Close()
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		if t.Name == l.LAN {
			return errors.New("защищённый LAN нельзя изменить")
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = t.Name
		attrs.Group = ownerGroup(t)
		attrs.Alias = ownerPrefix + t.ID
		attrs.MTU = t.MTU
		link := &netlink.Wireguard{LinkAttrs: attrs}
		if e = netlink.LinkAdd(link); e != nil {
			return errors.New("не удалось создать WireGuard: проверьте поддержку ядра и занятость имени")
		}
		actual, e := netlink.LinkByName(t.Name)
		if e != nil {
			return e
		}
		if actual.Attrs().Group != ownerGroup(t) {
			return errors.New("kernel did not preserve WireGuard ownership group")
		}
		if e = netlink.LinkSetAlias(actual, ownerPrefix+t.ID); e != nil {
			return e
		}
		key, e := l.Vault.Key(t.KeyRef, "tunnel")
		if e != nil {
			return e
		}
		port := t.ListenPort
		zero := 0
		cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port, FirewallMark: &zero, ReplacePeers: true}
		for _, p := range t.Peers {
			if !p.Enabled {
				continue
			}
			pub, _ := wgtypes.ParseKey(p.PublicKey)
			duration := time.Duration(p.Keepalive) * time.Second
			pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &duration}
			if p.PSKRef != "" {
				k, e := l.Vault.Key(p.PSKRef, "psk")
				if e != nil {
					return e
				}
				pc.PresharedKey = &k
			}
			if p.Endpoint != "" {
				pc.Endpoint, e = net.ResolveUDPAddr("udp", p.Endpoint)
				if e != nil {
					return errors.New("неверный WireGuard endpoint")
				}
			}
			for _, s := range p.AllowedIPs {
				n, _ := netip.ParsePrefix(s)
				pc.AllowedIPs = append(pc.AllowedIPs, *network(n))
			}
			cfg.Peers = append(cfg.Peers, pc)
		}
		if e = client.ConfigureDevice(t.Name, cfg); e != nil {
			return errors.New("не удалось настроить WireGuard: проверьте UDP-порт и поддержку ядра")
		}
		for _, s := range t.Addresses {
			n, _ := netip.ParsePrefix(s)
			if e = netlink.AddrAdd(actual, &netlink.Addr{IPNet: network(n), Flags: unix.IFA_F_NODAD}); e != nil {
				return e
			}
		}
		if e = netlink.LinkSetUp(actual); e != nil {
			return e
		}
		for _, r := range Routes(t) {
			route := &netlink.Route{LinkIndex: actual.Attrs().Index, Dst: network(r), Table: unix.RT_TABLE_MAIN, Protocol: routeProtocol, Priority: 100}
			if e = netlink.RouteAdd(route); e != nil {
				return fmt.Errorf("не удалось добавить маршрут %s", r)
			}
		}
	}
	return l.Verify(c)
}
func (l *Linux) Verify(c Config) error {
	for _, t := range c.Tunnels {
		if !t.Enabled {
			if link, e := netlink.LinkByName(t.Name); e == nil && claimable(link, t) {
				return errors.New("выключенный туннель WireGuard ещё существует")
			}
		}
	}
	if len(Active(c)) == 0 {
		return nil
	}
	client, e := wgctrl.New()
	if e != nil {
		return e
	}
	defer client.Close()
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		link, e := netlink.LinkByName(t.Name)
		if e != nil {
			return fmt.Errorf("туннель %s отсутствует", t.Name)
		}
		if !owned(link, t) || link.Attrs().Flags&net.FlagUp == 0 || link.Attrs().MTU != t.MTU {
			return fmt.Errorf("параметры %s изменились", t.Name)
		}
		if e = l.guardLink(link); e != nil {
			return e
		}
		dev, e := client.Device(t.Name)
		if e != nil {
			return e
		}
		key, e := l.Vault.Key(t.KeyRef, "tunnel")
		if e != nil {
			return e
		}
		if dev.Type != wgtypes.LinuxKernel || dev.PrivateKey != key || dev.ListenPort != t.ListenPort || dev.FirewallMark != 0 {
			return fmt.Errorf("ключ/порт %s изменён", t.Name)
		}
		gotAddresses, e := netlink.AddrList(link, netlink.FAMILY_ALL)
		if e != nil {
			return e
		}
		actual := []string{}
		for _, a := range gotAddresses {
			n, ok := asPrefix(a.IPNet)
			if ok && !n.Addr().IsLinkLocalUnicast() {
				actual = append(actual, n.String())
			}
		}
		wanted := append([]string{}, t.Addresses...)
		for i, s := range wanted {
			n, _ := netip.ParsePrefix(s)
			wanted[i] = n.String()
		}
		sort.Strings(actual)
		sort.Strings(wanted)
		if !reflect.DeepEqual(actual, wanted) {
			return fmt.Errorf("адреса %s изменены", t.Name)
		}
		peers := map[string]wgtypes.Peer{}
		for _, p := range dev.Peers {
			peers[p.PublicKey.String()] = p
		}
		count := 0
		for _, p := range t.Peers {
			if !p.Enabled {
				continue
			}
			count++
			got, ok := peers[p.PublicKey]
			if !ok || got.PersistentKeepaliveInterval != time.Duration(p.Keepalive)*time.Second {
				return errors.New("состав peers или keepalive изменён")
			}
			var psk wgtypes.Key
			if p.PSKRef != "" {
				psk, e = l.Vault.Key(p.PSKRef, "psk")
				if e != nil {
					return e
				}
			}
			if got.PresharedKey != psk {
				return errors.New("PSK peer изменён")
			}
			a := []string{}
			for _, n := range got.AllowedIPs {
				a = append(a, n.String())
			}
			b := append([]string{}, p.AllowedIPs...)
			sort.Strings(a)
			sort.Strings(b)
			if !reflect.DeepEqual(a, b) {
				return errors.New("AllowedIPs peer изменены")
			}
		}
		if count != len(dev.Peers) {
			return errors.New("обнаружены посторонние peers")
		}
		routes, e := netlink.RouteList(link, netlink.FAMILY_ALL)
		if e != nil {
			return e
		}
		a := []string{}
		for _, r := range routes {
			if r.Protocol == routeProtocol {
				a = append(a, routeKey(r.Dst))
			}
		}
		b := []string{}
		for _, r := range Routes(t) {
			b = append(b, r.String())
		}
		sort.Strings(a)
		sort.Strings(b)
		if !reflect.DeepEqual(a, b) {
			return errors.New("маршруты WireGuard изменены")
		}
	}
	return nil
}
func (l *Linux) Status(c Config) ([]TunnelStatus, error) {
	out := []TunnelStatus{}
	if len(Active(c)) == 0 {
		return out, nil
	}
	client, e := wgctrl.New()
	if e != nil {
		return out, e
	}
	defer client.Close()
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		s := TunnelStatus{Name: t.Name, Peers: []PeerStatus{}}
		link, e := netlink.LinkByName(t.Name)
		if e != nil {
			out = append(out, s)
			continue
		}
		if !owned(link, t) {
			return nil, errors.New("чужой интерфейс вместо WireGuard")
		}
		s.Up = link.Attrs().Flags&net.FlagUp != 0
		d, e := client.Device(t.Name)
		if e != nil {
			return nil, e
		}
		for _, p := range d.Peers {
			ps := PeerStatus{PublicKey: p.PublicKey.String(), RXBytes: p.ReceiveBytes, TXBytes: p.TransmitBytes}
			for _, wanted := range t.Peers {
				if wanted.PublicKey == ps.PublicKey {
					ps.ID = wanted.ID
					ps.Name = wanted.Name
				}
			}
			if p.Endpoint != nil {
				ps.Endpoint = p.Endpoint.String()
			}
			if !p.LastHandshakeTime.IsZero() {
				ps.LastHandshake = p.LastHandshakeTime.UTC().Format(time.RFC3339)
			}
			s.Peers = append(s.Peers, ps)
		}
		out = append(out, s)
	}
	return out, nil
}
