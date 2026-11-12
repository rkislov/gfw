package services

import (
	"errors"
	"fmt"
	dhcpconfig "github.com/rkislov/gfw/internal/engines/gdhcp/config"
	dnsengine "github.com/rkislov/gfw/internal/engines/gdns/core"
	"github.com/rkislov/gfw/internal/feed"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DNS  DNS  `json:"dns"`
	DHCP DHCP `json:"dhcp"`
}
type DNS struct {
	SecurityFeed   *feed.Filter `json:"security_feed,omitempty"`
	Enabled        bool         `json:"enabled"`
	Interface      string       `json:"interface"`
	Address        string       `json:"address"`
	Port           int          `json:"port"`
	Mode           string       `json:"mode"`
	Upstreams      []string     `json:"upstreams"`
	AllowedClients []string     `json:"allowed_clients"`
	CacheSize      int          `json:"cache_size"`
	DNSSEC         bool         `json:"dnssec"`
	Zones          []Zone       `json:"zones"`
}
type Zone struct {
	Name    string   `json:"name"`
	Records []string `json:"records"`
}
type DHCP struct {
	Enabled      bool   `json:"enabled"`
	Port         int    `json:"port"`
	LeaseSeconds int    `json:"lease_seconds"`
	Pools        []Pool `json:"pools"`
}
type Pool struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Interface    string        `json:"interface"`
	Address      string        `json:"address"`
	Network      string        `json:"network"`
	Start        string        `json:"start"`
	End          string        `json:"end"`
	Gateway      string        `json:"gateway"`
	DNS          []string      `json:"dns"`
	Domain       string        `json:"domain"`
	Reservations []Reservation `json:"reservations"`
}
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}
type Plan struct {
	CanApply bool     `json:"can_apply"`
	Actions  []string `json:"actions"`
	Warnings []string `json:"warnings"`
}

func Default() Config {
	return Config{DNS: DNS{Port: 53, Mode: "forward", Upstreams: []string{"1.1.1.1:53", "9.9.9.9:53"}, AllowedClients: []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}, CacheSize: 10000, Zones: []Zone{}}, DHCP: DHCP{Port: 67, LeaseSeconds: 3600, Pools: []Pool{}}}
}

var ifaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var objectID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func addr(s string, ipv4 bool) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" || a.IsLoopback() || a.IsLinkLocalUnicast() || ipv4 && !a.Is4() {
		return a, errors.New("нужен обычный IP-адрес интерфейса")
	}
	return a, nil
}
func validInterface(s string) bool { return ifaceName.MatchString(s) && s != "lo" }
func DNSConfig(c DNS) dnsengine.Config {
	out := dnsengine.DefaultConfig()
	out.DNSListen = net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	out.HTTPListen = "127.0.0.1:1"
	out.Mode = c.Mode
	out.Upstreams = c.Upstreams
	out.AllowedClients = c.AllowedClients
	out.CacheSize = c.CacheSize
	out.DNSSECValidation = c.DNSSEC
	out.QueryLog = true
	out.QueryLogLimit = 1000
	out.UDPWorkers = 1
	out.Zones = []dnsengine.Zone{}
	for _, z := range c.Zones {
		out.Zones = append(out.Zones, dnsengine.Zone{Name: z.Name, Kind: "primary", Records: z.Records, Clients: []string{}, Servers: []string{}})
	}
	if f := c.SecurityFeed; f != nil {
		out.Feeds = []dnsengine.Feed{{Name: "Security Feed", Enabled: true, Domains: f.Values}}
		out.FeedExceptions = f.Exceptions
	}
	return out
}
func DHCPConfig(c DHCP, p Pool, db string) *dhcpconfig.Config {
	out := &dhcpconfig.Config{}
	out.ApplyDefaults()
	out.Server.Listen = ":" + strconv.Itoa(c.Port)
	out.Server.ServerID = p.Address
	out.Server.BoundInterface = p.Interface
	out.Server.Interfaces = []dhcpconfig.Interface{{Name: p.Interface, Mode: "access"}}
	out.Server.ManageLinks = false
	out.Server.RawVLAN = false
	out.Server.Authoritative = true
	out.Server.PingCheck = false
	out.Server.LeaseDefault = time.Duration(c.LeaseSeconds) * time.Second
	out.Server.LeaseMax = out.Server.LeaseDefault
	out.Database.Driver = "sqlite"
	out.Database.DSN = db
	out.Relay.Enabled = false
	out.Relay.UnknownVLANAction = "ignore"
	out.Web.Enabled = false
	out.Metrics.Enabled = false
	out.DDNS.Enabled = false
	out.HA.Enabled = false
	sub := dhcpconfig.Subnet{ID: p.ID, Network: p.Network, Range: []string{p.Start, p.End}, Gateway: p.Gateway, DNS: p.DNS, Domain: p.Domain}
	for _, r := range p.Reservations {
		sub.Reservations = append(sub.Reservations, dhcpconfig.Reservation{MAC: r.MAC, IP: r.IP, Hostname: r.Hostname})
	}
	out.Subnets = []dhcpconfig.Subnet{sub}
	return out
}
func usable(n netip.Prefix, a netip.Addr) bool {
	return a.Is4() && n.Contains(a) && a != n.Addr() && n.Contains(a.Next())
}
func Validate(c Config) error {
	if err := c.DNS.SecurityFeed.Validate("domain"); err != nil {
		return err
	}
	if c.DNS.Port < 1 || c.DNS.Port > 65535 || c.DHCP.Port < 1 || c.DHCP.Port > 65535 {
		return errors.New("порт сервиса должен быть 1–65535")
	}
	if c.DNS.Mode != "forward" && c.DNS.Mode != "recursive" {
		return errors.New("DNS: выберите forward или recursive")
	}
	if c.DNS.CacheSize < 0 || c.DNS.CacheSize > 1000000 || len(c.DNS.Zones) > 128 || len(c.DHCP.Pools) > 32 {
		return errors.New("превышен лимит кеша, зон или пулов")
	}
	if c.DHCP.LeaseSeconds < 60 || c.DHCP.LeaseSeconds > 604800 {
		return errors.New("срок DHCP-аренды: 60–604800 секунд")
	}
	if c.DNS.Enabled {
		if !validInterface(c.DNS.Interface) {
			return errors.New("выберите интерфейс DNS")
		}
		if _, e := addr(c.DNS.Address, false); e != nil {
			return fmt.Errorf("DNS: %w", e)
		}
		if len(c.DNS.AllowedClients) == 0 {
			return errors.New("DNS: явно задайте разрешённые сети клиентов")
		}
		if len(c.DNS.AllowedClients) > 128 || len(c.DNS.Upstreams) > 16 {
			return errors.New("DNS: слишком много клиентов/upstream")
		}
		for _, p := range c.DNS.AllowedClients {
			n, e := netip.ParsePrefix(p)
			if e != nil || n != n.Masked() || n.Addr().Is4In6() {
				return errors.New("DNS ACL: укажите корректные сети CIDR")
			}
		}
		if _, e := dnsengine.New(DNSConfig(c.DNS)); e != nil {
			return fmt.Errorf("DNS: %w", e)
		}
	}
	seen := map[string]bool{}
	interfaces := map[string]bool{}
	prefixes := []netip.Prefix{}
	for _, p := range c.DHCP.Pools {
		if !objectID.MatchString(p.ID) || seen[p.ID] || strings.TrimSpace(p.Name) == "" || len(p.Name) > 200 {
			return errors.New("пулу нужны уникальный ID и название")
		}
		seen[p.ID] = true
		if !validInterface(p.Interface) || interfaces[p.Interface] {
			return errors.New("DHCP: один пул на интерфейс; выберите отдельный интерфейс/VLAN")
		}
		interfaces[p.Interface] = true
		a, e := addr(p.Address, true)
		if e != nil {
			return fmt.Errorf("DHCP: %w", e)
		}
		n, e := netip.ParsePrefix(p.Network)
		if e != nil || !n.Addr().Is4() || n != n.Masked() || n.Bits() > 30 || !usable(n, a) {
			return errors.New("DHCP: адрес сервера должен входить в IPv4-подсеть /1–/30")
		}
		if n.Bits() < 1 {
			return errors.New("DHCP: сеть /0 недопустима")
		}
		for _, other := range prefixes {
			if n.Overlaps(other) {
				return errors.New("DHCP: подсети пулов не должны пересекаться")
			}
		}
		prefixes = append(prefixes, n)
		start, e := netip.ParseAddr(p.Start)
		if e != nil || !start.Is4() {
			return errors.New("DHCP: неверное начало диапазона")
		}
		end, e := netip.ParseAddr(p.End)
		if e != nil || !end.Is4() || start.Compare(end) > 0 || !usable(n, start) || !usable(n, end) {
			return errors.New("DHCP: диапазон должен входить в подсеть")
		}
		if a.Compare(start) >= 0 && a.Compare(end) <= 0 {
			return errors.New("DHCP: адрес сервера не должен входить в выдаваемый диапазон")
		}
		gateway, e := addr(p.Gateway, true)
		if e != nil || !usable(n, gateway) || gateway.Compare(start) >= 0 && gateway.Compare(end) <= 0 {
			return errors.New("DHCP: шлюз должен быть в подсети, вне диапазона выдачи")
		}
		if len(p.Reservations) > 1024 || len(p.DNS) < 1 || len(p.DNS) > 4 {
			return errors.New("DHCP: нужны 1–4 DNS-сервера и не более 1024 резерваций")
		}
		for _, ip := range p.DNS {
			if _, e := addr(ip, true); e != nil {
				return errors.New("DHCP: неверный DNS IPv4")
			}
		}
		reservationMACs, reservationIPs := map[string]bool{}, map[string]bool{}
		for _, r := range p.Reservations {
			mac, e := net.ParseMAC(r.MAC)
			ip, ie := netip.ParseAddr(r.IP)
			if e != nil || len(mac) != 6 || mac[0]&1 != 0 || ie != nil || !usable(n, ip) || ip == a || ip == gateway || reservationMACs[mac.String()] || reservationIPs[ip.String()] {
				return errors.New("DHCP: некорректная резервация или занятый адрес")
			}
			reservationMACs[mac.String()] = true
			reservationIPs[ip.String()] = true
		}
		if e := DHCPConfig(c.DHCP, p, "/gfw/private/leases.db").Validate(); e != nil {
			return fmt.Errorf("DHCP %s: %w", p.Name, e)
		}
	}
	if c.DHCP.Enabled && len(c.DHCP.Pools) == 0 {
		return errors.New("DHCP: добавьте хотя бы один пул")
	}
	return nil
}
func Interfaces(c Config) map[string][]string {
	out := map[string][]string{}
	if c.DNS.Enabled {
		out[c.DNS.Interface] = append(out[c.DNS.Interface], c.DNS.Address)
	}
	if c.DHCP.Enabled {
		for _, p := range c.DHCP.Pools {
			out[p.Interface] = append(out[p.Interface], p.Address)
		}
	}
	return out
}
func Preview(c Config) Plan {
	actions := []string{}
	if c.DNS.Enabled {
		actions = append(actions, "DNS UDP/TCP: "+net.JoinHostPort(c.DNS.Address, strconv.Itoa(c.DNS.Port))+" на "+c.DNS.Interface)
	} else {
		actions = append(actions, "DNS выключен")
	}
	if f := c.DNS.SecurityFeed; f != nil {
		actions = append(actions, fmt.Sprintf("Security Feed DNS: %d доменов, %d исключений; SHA-256 %s", len(f.Values), len(f.Exceptions), f.SHA256))
	}
	if c.DHCP.Enabled {
		for _, p := range c.DHCP.Pools {
			actions = append(actions, fmt.Sprintf("DHCP %s: %s–%s на %s", p.Name, p.Start, p.End, p.Interface))
		}
	} else {
		actions = append(actions, "DHCP выключен")
	}
	return Plan{Actions: actions, Warnings: []string{"Сервисы не меняют правила firewall: разрешите DNS TCP/UDP и DHCP UDP в выбранных сетях отдельными правилами.", "Новые DNS-настройки перезапускают слушатели; журнал запросов находится в памяти. DHCP-аренды сохраняются в отдельных SQLite-файлах.", "Откат возвращает конфигурацию сервисов, но уже выданные DHCP-аренды у клиентов сохраняются до истечения срока."}}
}
