package ipsec

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/vpncred"
)

type Tunnel struct {
	Auth              *identity.Method `json:"auth,omitempty"`
	PublicEndpoint    string           `json:"public_endpoint,omitempty"`
	ClientUser        string           `json:"client_user,omitempty"`
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	Interface         string           `json:"interface"`
	Enabled           bool             `json:"enabled"`
	Initiate          bool             `json:"initiate"`
	LocalAddress      string           `json:"local_address"`
	RemoteAddress     string           `json:"remote_address"`
	LocalNetworks     []string         `json:"local_networks"`
	RemoteNetworks    []string         `json:"remote_networks"`
	CertificateID     string           `json:"certificate_id"`
	PeerCertificateID string           `json:"peer_certificate_id"`
}

type Config struct {
	Tunnels []Tunnel `json:"tunnels"`
}

func Empty() Config { return Config{Tunnels: []Tunnel{}} }

var endpointPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

var ifName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)
var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

func allowed(p netip.Prefix) bool {
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
		return false
	}
	for _, r := range special {
		if p.Overlaps(r) {
			return false
		}
	}
	return true
}
func ValidateTunnel(t Tunnel) error {
	if !vpncred.IDPattern.MatchString(t.ID) || !ifName.MatchString(t.Interface) || t.Interface == "lo" || strings.TrimSpace(t.Name) == "" || len(t.Name) > 100 || strings.ContainsAny(t.Name, "\r\n\x00") {
		return errors.New("нужны ID, название и допустимое имя XFRM-интерфейса")
	}
	if !vpncred.IDPattern.MatchString(t.CertificateID) || (t.Auth == nil || t.Auth.Certificate) && !vpncred.IDPattern.MatchString(t.PeerCertificateID) || t.CertificateID == t.PeerCertificateID {
		return errors.New("выберите два разных сертификата")
	}
	local, le := netip.ParseAddr(t.LocalAddress)
	peer, pe := netip.ParseAddr(t.RemoteAddress)
	if le != nil || !local.Is4() || !allowed(netip.PrefixFrom(local, 32)) {
		return errors.New("нужен локальный IPv4-адрес IKE")
	}
	if t.Auth == nil {
		if pe != nil || local == peer || !allowed(netip.PrefixFrom(peer, 32)) || t.PublicEndpoint != "" || t.ClientUser != "" {
			return errors.New("нужен отличный от локального числовой IPv4-адрес второго IKE-шлюза")
		}
	} else {
		if err := t.Auth.Validate(); err != nil {
			return err
		}
		if !t.Auth.Credentials() || !endpointPattern.MatchString(t.PublicEndpoint) || t.RemoteAddress != "" || t.Initiate || len(t.RemoteNetworks) != 1 ||
			t.Auth.Certificate && !identity.Username.MatchString(t.ClientUser) ||
			!t.Auth.Certificate && (t.ClientUser != "" || t.PeerCertificateID != "") {
			return errors.New("для доступа IKEv2 нужны публичное имя, пул адресов и EAP-GTC; при комбинации с сертификатом нужен логин владельца")
		}
		pool, e := netip.ParsePrefix(t.RemoteNetworks[0])
		if e != nil || pool.Bits() < 16 || pool.Bits() > 30 {
			return errors.New("пул IKEv2 должен быть подсетью IPv4 /16–/30")
		}
	}
	for _, nets := range [][]string{t.LocalNetworks, t.RemoteNetworks} {
		if len(nets) == 0 || len(nets) > 8 {
			return errors.New("укажите от 1 до 8 подсетей с каждой стороны")
		}
		for i, s := range nets {
			p, e := netip.ParsePrefix(s)
			if e != nil || !allowed(p) {
				return errors.New("нужна каноническая IPv4-подсеть, без маршрута по умолчанию или служебных адресов")
			}
			for _, other := range nets[:i] {
				if p.Overlaps(netip.MustParsePrefix(other)) {
					return errors.New("селекторы одной стороны пересекаются")
				}
			}
		}
	}
	for _, s := range t.RemoteNetworks {
		p := netip.MustParsePrefix(s)
		if p.Contains(local) || p.Contains(peer) {
			return errors.New("удалённая сеть захватывает адрес шлюза IKE")
		}
		for _, v := range t.LocalNetworks {
			if p.Overlaps(netip.MustParsePrefix(v)) {
				return errors.New("локальные и удалённые сети пересекаются")
			}
		}
	}
	return nil
}
func Validate(c Config) error {
	if len(c.Tunnels) > 8 {
		return errors.New("не более 8 туннелей IPsec")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	var remote []netip.Prefix
	access := false
	for _, t := range c.Tunnels {
		if e := ValidateTunnel(t); e != nil {
			return fmt.Errorf("%s: %w", t.Name, e)
		}
		if ids[t.ID] || names[t.Interface] {
			return errors.New("ID и имена интерфейсов должны быть уникальны")
		}
		ids[t.ID] = true
		names[t.Interface] = true
		if !t.Enabled {
			continue
		}
		if t.Auth != nil {
			if access {
				return errors.New("поддерживается один активный профиль удалённого доступа IKEv2")
			}
			access = true
		}
		for _, s := range t.RemoteNetworks {
			p := netip.MustParsePrefix(s)
			for _, prev := range remote {
				if p.Overlaps(prev) {
					return errors.New("удалённые сети туннелей пересекаются")
				}
			}
			for _, other := range c.Tunnels {
				if address, _ := netip.ParseAddr(other.RemoteAddress); other.Enabled && p.Contains(address) {
					return errors.New("маршрут IPsec захватывает адрес другого IKE-шлюза")
				}
			}
			remote = append(remote, p)
		}
	}
	return nil
}
func Active(c Config) map[string]Tunnel {
	result := map[string]Tunnel{}
	for _, t := range c.Tunnels {
		if t.Enabled {
			result[t.Interface] = t
		}
	}
	return result
}

type Plan struct {
	CanApply bool     `json:"can_apply"`
	Actions  []string `json:"actions"`
	Warnings []string `json:"warnings"`
}

func Preview(c Config) Plan {
	p := Plan{Actions: []string{}, Warnings: []string{
		"Агент создаёт XFRM-интерфейсы и маршруты к удалённым сетям. Доступ к UDP 500/4500 и трафику VPN задаётся правилами firewall.",
		"Изменение требует подтверждения. Обновление CRL разрывает сеансы и сохраняется при откате конфигурации.",
	}}
	for _, t := range c.Tunnels {
		if t.Enabled {
			p.Actions = append(p.Actions, fmt.Sprintf("%s · %s → %s · %s", t.Name, t.LocalAddress, t.RemoteAddress, t.Interface))
		}
	}
	return p
}

type PeerSession struct {
	IKEID    uint32 `json:"ike_id,omitempty"`
	Identity string `json:"identity"`
	Username string `json:"username,omitempty"`
}

func (s PeerSession) User() string {
	if s.Username != "" {
		return s.Username
	}
	return s.Identity
}

type Status struct {
	ID          string        `json:"id"`
	Loaded      bool          `json:"loaded"`
	Established bool          `json:"established"`
	Blocked     string        `json:"blocked,omitempty"`
	CRLNumber   int64         `json:"crl_number"`
	Details     string        `json:"details,omitempty"`
	Sessions    []PeerSession `json:"sessions,omitempty"`
}
type Backend interface {
	Stage([]Material, Config) error
	Refresh([]vpncred.CRLUpdate, Config) error
	CAs(Config) []string
	Prepare(Config, Config) (Plan, error)
	Activate(Config, Config) error
	Verify(Config) error
	Status(Config) ([]Status, error)
	Disconnect(Tunnel, uint32, string) error
	Logs() ([]string, error)
	Maintain(Config) error
	Close() error
}

func IKEIdentity(value string) string {
	if _, err := netip.ParseAddr(value); err == nil {
		return value
	}
	return "@" + value
}
