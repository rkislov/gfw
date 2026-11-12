package wireguard

import (
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

type Config struct {
	Tunnels []Tunnel `json:"tunnels"`
}
type Tunnel struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	KeyRef         string   `json:"key_ref"`
	PublicKey      string   `json:"public_key"`
	ListenPort     int      `json:"listen_port"`
	MTU            int      `json:"mtu"`
	Addresses      []string `json:"addresses"`
	InstallRoutes  bool     `json:"install_routes"`
	ClientEndpoint string   `json:"client_endpoint"`
	Peers          []Peer   `json:"peers"`
}
type Peer struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	PublicKey       string   `json:"public_key"`
	KeyRef          string   `json:"key_ref"`
	PSKRef          string   `json:"psk_ref"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	Keepalive       int      `json:"keepalive"`
	ClientAddresses []string `json:"client_addresses"`
	ClientRoutes    []string `json:"client_routes"`
	ClientDNS       []string `json:"client_dns"`
}
type Plan struct {
	CanApply bool     `json:"can_apply"`
	Actions  []string `json:"actions"`
	Warnings []string `json:"warnings"`
}
type PeerStatus struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint"`
	LastHandshake string `json:"last_handshake,omitempty"`
	RXBytes       int64  `json:"rx_bytes"`
	TXBytes       int64  `json:"tx_bytes"`
}
type TunnelStatus struct {
	Name  string       `json:"name"`
	Up    bool         `json:"up"`
	Peers []PeerStatus `json:"peers"`
}

func Empty() Config { return Config{Tunnels: []Tunnel{}} }
func Canonical(c Config) Config {
	if c.Tunnels == nil {
		c.Tunnels = []Tunnel{}
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Addresses == nil {
			t.Addresses = []string{}
		}
		if t.Peers == nil {
			t.Peers = []Peer{}
		}
		for j := range t.Peers {
			p := &t.Peers[j]
			if p.AllowedIPs == nil {
				p.AllowedIPs = []string{}
			}
			if p.ClientAddresses == nil {
				p.ClientAddresses = []string{}
			}
			if p.ClientRoutes == nil {
				p.ClientRoutes = []string{}
			}
			if p.ClientDNS == nil {
				p.ClientDNS = []string{}
			}
		}
	}
	return c
}

var IDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var NamePattern = regexp.MustCompile(`^wg[a-zA-Z0-9_-]{0,13}$`)

func publicKey(s string) error {
	k, e := wgtypes.ParseKey(s)
	if e != nil || k == (wgtypes.Key{}) {
		return errors.New("нужен публичный ключ WireGuard в base64")
	}
	return nil
}
func hostPrefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || p.Addr().Is4In6() || !p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() || p.Bits() == 0 {
		return p, errors.New("нужен обычный IP/префикс туннеля")
	}
	if p.Addr().Is4() && p.Bits() < 31 {
		if p.Addr() == p.Masked().Addr() || !p.Contains(p.Addr().Next()) {
			return p, errors.New("адрес сети/broadcast нельзя назначить туннелю")
		}
	}
	return p, nil
}
func prefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
		return p, errors.New("нужен корректный CIDR без битов хоста")
	}
	return p, nil
}
func endpoint(s string, ipOnly bool) error {
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return errors.New("endpoint: IP:порт или [IPv6]:порт")
	}
	_, e = netip.ParseAddrPort(s)
	if ipOnly && e != nil {
		return errors.New("endpoint узла: укажите IP, DNS endpoint пока доступен только в клиентском экспорте")
	}
	if !ipOnly {
		a, e := netip.ParseAddr(h)
		if e != nil {
			if !regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`).MatchString(h) || strings.Contains(h, "..") {
				return errors.New("некорректное DNS-имя endpoint")
			}
		} else if a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return errors.New("некорректный endpoint")
		}
	} else {
		a, _ := netip.ParseAddrPort(s)
		if a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().Zone() != "" {
			return errors.New("некорректный endpoint")
		}
	}
	var port int
	if _, e = fmt.Sscanf(p, "%d", &port); e != nil || fmt.Sprint(port) != p || port < 1 || port > 65535 {
		return errors.New("порт endpoint: 1–65535")
	}
	return nil
}
func Validate(c Config) error {
	if len(c.Tunnels) > 16 {
		return errors.New("не более 16 туннелей WireGuard")
	}
	ids, names, ports := map[string]bool{}, map[string]bool{}, map[int]bool{}
	routed := []netip.Prefix{}
	addresses := []netip.Prefix{}
	for _, t := range c.Tunnels {
		if !IDPattern.MatchString(t.ID) || ids[t.ID] || !NamePattern.MatchString(t.Name) || names[t.Name] {
			return errors.New("нужны уникальные ID и имя интерфейса wg… до 15 символов")
		}
		ids[t.ID] = true
		names[t.Name] = true
		if !IDPattern.MatchString(t.KeyRef) || publicKey(t.PublicKey) != nil {
			return errors.New("создайте ключ туннеля в агенте")
		}
		if t.ListenPort < 1 || t.ListenPort > 65535 || t.MTU < 576 || t.MTU > 9000 {
			return errors.New("нужны UDP-порт 1–65535 и MTU 576–9000")
		}
		if t.Enabled && ports[t.ListenPort] {
			return errors.New("UDP-порты туннелей должны различаться")
		}
		if t.Enabled {
			ports[t.ListenPort] = true
		}
		if len(t.Addresses) < 1 || len(t.Addresses) > 16 || len(t.Peers) > 256 {
			return errors.New("туннель: 1–16 адресов и не более 256 peers")
		}
		ownIPs := map[netip.Addr]bool{}
		for _, s := range t.Addresses {
			p, e := hostPrefix(s)
			if e != nil {
				return e
			}
			if p.Addr().Is6() && t.MTU < 1280 {
				return errors.New("IPv6 требует MTU не менее 1280")
			}
			if ownIPs[p.Addr()] {
				return errors.New("адрес туннеля повторяется")
			}
			ownIPs[p.Addr()] = true
			if t.Enabled {
				for _, other := range addresses {
					if p.Overlaps(other) {
						return errors.New("подсети адресов туннелей пересекаются")
					}
				}
				addresses = append(addresses, p)
			}
		}
		if t.ClientEndpoint != "" {
			if e := endpoint(t.ClientEndpoint, false); e != nil {
				return e
			}
		}
		peerKeys := map[string]bool{}
		allowed := []netip.Prefix{}
		for _, p := range t.Peers {
			if !IDPattern.MatchString(p.ID) || ids[p.ID] || strings.TrimSpace(p.Name) == "" || len(p.Name) > 200 {
				return errors.New("peer: нужны уникальный ID и название")
			}
			ids[p.ID] = true
			if e := publicKey(p.PublicKey); e != nil {
				return e
			}
			if p.PublicKey == t.PublicKey || peerKeys[p.PublicKey] {
				return errors.New("ключ peer повторяется или совпадает с ключом туннеля")
			}
			peerKeys[p.PublicKey] = true
			if p.KeyRef != "" && !IDPattern.MatchString(p.KeyRef) || p.PSKRef != "" && !IDPattern.MatchString(p.PSKRef) {
				return errors.New("неверная ссылка на ключ")
			}
			if p.Keepalive < 0 || p.Keepalive > 65535 || len(p.AllowedIPs) < 1 || len(p.AllowedIPs) > 128 {
				return errors.New("peer: нужны AllowedIPs и keepalive 0–65535")
			}
			if p.Endpoint != "" {
				if e := endpoint(p.Endpoint, true); e != nil {
					return e
				}
			}
			for _, s := range p.AllowedIPs {
				n, e := prefix(s)
				if e != nil {
					return e
				}
				if t.Enabled && p.Enabled {
					for _, a := range ownIPsAsSlice(ownIPs) {
						if n.Contains(a) {
							return errors.New("AllowedIPs peer содержат собственный адрес туннеля")
						}
					}
					for _, other := range allowed {
						if n.Overlaps(other) {
							return errors.New("AllowedIPs активных peers одного туннеля не должны пересекаться")
						}
					}
					allowed = append(allowed, n)
					if t.InstallRoutes {
						if n.Bits() == 0 {
							return errors.New("автоматический default route пока запрещён; используйте отдельные подсети")
						}
						for _, other := range routed {
							if n.Overlaps(other) {
								return errors.New("маршруты AllowedIPs разных туннелей пересекаются")
							}
						}
						routed = append(routed, n)
					}
				}
			}
			if len(p.ClientAddresses) > 16 || len(p.ClientRoutes) > 128 || len(p.ClientDNS) > 4 {
				return errors.New("превышены лимиты клиентского профиля")
			}
			for _, s := range p.ClientAddresses {
				a, e := hostPrefix(s)
				if e != nil {
					return e
				}
				covered := false
				for _, x := range p.AllowedIPs {
					n, _ := netip.ParsePrefix(x)
					if n.Contains(a.Addr()) {
						covered = true
					}
				}
				if !covered || ownIPs[a.Addr()] {
					return errors.New("адрес клиента должен входить в AllowedIPs peer и отличаться от адреса сервера")
				}
			}
			for _, s := range p.ClientRoutes {
				if _, e := prefix(s); e != nil {
					return e
				}
			}
			for _, s := range p.ClientDNS {
				a, e := netip.ParseAddr(s)
				if e != nil || !a.IsGlobalUnicast() || a.Is4In6() {
					return errors.New("DNS клиента: нужен обычный IP")
				}
			}
		}
	}

	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		for _, other := range c.Tunnels {
			if !other.Enabled {
				continue
			}
			for _, s := range other.Addresses {
				n, _ := netip.ParsePrefix(s)
				if t.Name != other.Name {
					for _, r := range Routes(t) {
						if r.Overlaps(n) {
							return errors.New("маршрут peer пересекает адресную сеть другого туннеля")
						}
					}
				}
				for _, p := range t.Peers {
					if p.Enabled && p.Endpoint != "" {
						ep, _ := netip.ParseAddrPort(p.Endpoint)
						if n.Contains(ep.Addr()) {
							return errors.New("endpoint peer попадает в адресную сеть туннеля")
						}
					}
				}
			}
		}
		for _, p := range t.Peers {
			if !p.Enabled || p.Endpoint == "" {
				continue
			}
			ep, _ := netip.ParseAddrPort(p.Endpoint)
			for _, other := range c.Tunnels {
				for _, r := range Routes(other) {
					if r.Contains(ep.Addr()) {
						return errors.New("маршрут туннеля перехватит внешний endpoint peer")
					}
				}
			}
		}
	}

	return nil
}
func ownIPsAsSlice(m map[netip.Addr]bool) []netip.Addr {
	out := []netip.Addr{}
	for a := range m {
		out = append(out, a)
	}
	return out
}
func Preview(c Config) Plan {
	p := Plan{Actions: []string{}, Warnings: []string{"WireGuard не открывает firewall и не включает forwarding. Разрешите UDP-порт входа и нужный трафик из зоны VPN отдельно.", "Применение пересоздаёт управляемые туннели: соединения и счётчики могут кратковременно сброситься. Неподтверждённые изменения откатываются.", "Автоматические маршруты ограничены отдельными подсетями; замена основного шлюза и policy routing пока не поддерживаются."}}
	for _, t := range c.Tunnels {
		if t.Enabled {
			p.Actions = append(p.Actions, fmt.Sprintf("%s: UDP/%d, адреса %s", t.Name, t.ListenPort, strings.Join(t.Addresses, ", ")))
		} else {
			p.Actions = append(p.Actions, t.Name+": выключить")
		}
	}
	return p
}
func Active(c Config) map[string]Tunnel {
	out := map[string]Tunnel{}
	for _, t := range c.Tunnels {
		if t.Enabled {
			out[t.Name] = t
		}
	}
	return out
}
func Routes(t Tunnel) []netip.Prefix {
	out := []netip.Prefix{}
	if !t.Enabled || !t.InstallRoutes {
		return out
	}
	for _, p := range t.Peers {
		if p.Enabled {
			for _, s := range p.AllowedIPs {
				n, _ := netip.ParsePrefix(s)
				out = append(out, n)
			}
		}
	}
	return out
}
