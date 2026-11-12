// Package openvpn builds structured OpenVPN client profiles. It never runs
// commands or accepts arbitrary OpenVPN directives.
package openvpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/rkislov/gfw/internal/identity"
)

var IDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func usableIPv4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range reservedIPv4 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Profile struct {
	Auth                *identity.Method `json:"auth,omitempty"`
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	ServerCertificateID string           `json:"server_certificate_id"`
	ClientCertificateID string           `json:"client_certificate_id"`
	Remote              string           `json:"remote"`
	Port                int              `json:"port"`
	Protocol            string           `json:"protocol"`
	Routes              []string         `json:"routes"`
	DNS                 []string         `json:"dns"`
}
type Config struct {
	Profiles []Profile `json:"profiles"`
}

func Empty() Config { return Config{Profiles: []Profile{}} }
func ValidRemote(s string) bool {
	if s != strings.ToLower(s) || len(s) > 253 || s == "" {
		return false
	}
	if a, e := netip.ParseAddr(s); e == nil {
		if a.Is4() {
			return usableIPv4(a)
		}
		return a.Zone() == "" && !a.Is4In6() && a.IsGlobalUnicast()
	}
	// Malformed IP literals must not be interpreted as a DNS name.
	if strings.ContainsAny(s, ":/[]") || net.ParseIP(s) != nil {
		return false
	}
	numeric := true
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			numeric = false
		}
	}
	if numeric {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func ValidateProfile(p Profile) error {
	if !IDPattern.MatchString(p.ID) || !IDPattern.MatchString(p.ServerCertificateID) || (p.Auth == nil || p.Auth.Certificate) && !IDPattern.MatchString(p.ClientCertificateID) || p.Auth != nil && !p.Auth.Certificate && p.ClientCertificateID != "" {
		return errors.New("нужны ID профиля и ссылки на сертификаты GFW")
	}
	if p.Auth != nil {
		if err := p.Auth.Validate(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 || strings.ContainsAny(p.Name, "\x00\r\n") {
		return errors.New("название профиля: 1–100 символов без переводов строк")
	}
	if !ValidRemote(p.Remote) || p.Port < 1 || p.Port > 65535 || (p.Protocol != "udp" && p.Protocol != "tcp") {
		return errors.New("нужны адрес сервера без схемы/порта, порт 1–65535 и протокол udp/tcp")
	}
	if len(p.Routes) > 64 || len(p.DNS) > 4 {
		return errors.New("не более 64 маршрутов и 4 DNS-серверов")
	}
	seen := map[string]bool{}
	for _, s := range p.Routes {
		n, e := netip.ParsePrefix(s)
		if e != nil || !n.Addr().Is4() || n.Bits() == 0 || n != n.Masked() || !n.Addr().IsGlobalUnicast() {
			return errors.New("маршруты: канонические IPv4-подсети /1–/32, без multicast/loopback и маршрута по умолчанию")
		}

		for _, reserved := range reservedIPv4 {
			if n.Overlaps(reserved) {
				return errors.New("маршрут охватывает служебные адреса IPv4")
			}
		}
		if seen[s] {
			return errors.New("маршрут повторяется")
		}
		seen[s] = true
	}
	seen = map[string]bool{}
	for _, s := range p.DNS {
		a, e := netip.ParseAddr(s)
		if e != nil || !usableIPv4(a) || s != a.String() || seen[s] {
			return errors.New("DNS: до 4 разных IPv4-адресов без служебных адресов")
		}
		seen[s] = true
	}
	return nil
}
func Validate(c Config) error {
	if len(c.Profiles) > 128 {
		return errors.New("не более 128 профилей OpenVPN")
	}
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		if e := ValidateProfile(p); e != nil {
			return fmt.Errorf("профиль %q: %w", p.Name, e)
		}
		if seen[p.ID] {
			return errors.New("ID профиля повторяется")
		}
		seen[p.ID] = true
	}
	return nil
}

// Render receives validated PEM material from the PKI vault, never from HTTP.
// The server is pinned by its exact leaf SHA256 fingerprint, in addition to CA
// and EKU validation. Remote route/DNS pushes are ignored by route-nopull.
func Render(p Profile, ca, cert, key []byte, fingerprint string) (string, error) {
	if e := ValidateProfile(p); e != nil {
		return "", e
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fingerprint) {
		return "", errors.New("неверный SHA256 сервера")
	}
	fp := make([]string, 32)
	for i := range fp {
		fp[i] = fingerprint[2*i : 2*i+2]
	}
	proto := "udp"
	if p.Protocol == "tcp" {
		proto = "tcp-client"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# GFW OpenVPN client; OpenVPN 2.6+\n# Contains a private client key. Keep this file secret.\nclient\ndev tun\nproto %s\nremote %s %d\nnobind\nresolv-retry infinite\npersist-key\npersist-tun\nauth-nocache\nremote-cert-tls server\npeer-fingerprint %s\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\nallow-compression no\nroute-nopull\nverb 3\n", proto, p.Remote, p.Port, strings.Join(fp, ":"))
	if p.Auth != nil && p.Auth.Credentials() {
		b.WriteString("auth-user-pass\n")
	}
	for _, s := range p.Routes {
		n, _ := netip.ParsePrefix(s)
		mask := net.IP(net.CIDRMask(n.Bits(), 32)).String()
		fmt.Fprintf(&b, "route %s %s\n", n.Addr(), mask)
	}
	for _, s := range p.DNS {
		fmt.Fprintf(&b, "dhcp-option DNS %s\n", s)
	}
	for _, block := range []struct {
		name string
		data []byte
	}{{"ca", ca}, {"cert", cert}, {"key", key}} {
		if len(block.data) == 0 {
			continue
		}
		fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", block.name, strings.TrimSpace(string(block.data)), block.name)
	}
	return b.String(), nil
}
