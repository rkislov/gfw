package openvpn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/vpncred"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Client struct {
	Username      string `json:"username,omitempty"`
	CertificateID string `json:"certificate_id"`
	Address       string `json:"address"`
}
type Instance struct {
	Auth                *identity.Method `json:"auth,omitempty"`
	PublicEndpoint      string           `json:"public_endpoint,omitempty"`
	ClientRoutes        []string         `json:"client_routes,omitempty"`
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	Interface           string           `json:"interface"`
	Mode                string           `json:"mode"`
	Enabled             bool             `json:"enabled"`
	CertificateID       string           `json:"certificate_id"`
	ServerCertificateID string           `json:"server_certificate_id,omitempty"`
	Address             string           `json:"address"`
	BindAddress         string           `json:"bind_address,omitempty"`
	Remote              string           `json:"remote,omitempty"`
	Port                int              `json:"port"`
	Protocol            string           `json:"protocol"`
	Routes              []string         `json:"routes"`
	Clients             []Client         `json:"clients"`
}
type RuntimeConfig struct {
	Instances []Instance `json:"instances"`
}

func RuntimeEmpty() RuntimeConfig { return RuntimeConfig{Instances: []Instance{}} }

// Materials are accepted only on the private controller-agent socket. They must
// never be marshalled into a journal, public state or configuration database.
type Material struct {
	Instance    Instance          `json:"instance"`
	CAID        string            `json:"ca_id"`
	CA          []byte            `json:"ca"`
	Certificate []byte            `json:"certificate"`
	Key         []byte            `json:"key"`
	Peers       map[string][]byte `json:"peers"`
	CRL         []byte            `json:"crl"`
}
type CRLUpdate = vpncred.CRLUpdate
type Plan struct {
	CanApply bool     `json:"can_apply"`
	Actions  []string `json:"actions"`
	Warnings []string `json:"warnings"`
}
type Session struct {
	ClientID *uint32 `json:"client_id,omitempty"`
	Name     string  `json:"name"`
	Username string  `json:"username,omitempty"`
	Address  string  `json:"address"`
	Remote   string  `json:"remote"`
	RXBytes  uint64  `json:"rx_bytes"`
	TXBytes  uint64  `json:"tx_bytes"`
}

func (s Session) User() string {
	if s.Username != "" {
		return s.Username
	}
	return s.Name
}

type Status struct {
	ID            string    `json:"id"`
	Interface     string    `json:"interface"`
	Mode          string    `json:"mode"`
	Running       bool      `json:"running"`
	Ready         bool      `json:"ready"`
	Blocked       string    `json:"blocked,omitempty"`
	State         string    `json:"state"`
	Sessions      []Session `json:"sessions"`
	SessionsError bool      `json:"sessions_error,omitempty"`
	CRLNumber     int64     `json:"crl_number"`
}
type Backend interface {
	Stage([]Material, RuntimeConfig) error
	Refresh([]CRLUpdate, RuntimeConfig) error
	CAs(RuntimeConfig) []string
	Prepare(RuntimeConfig, RuntimeConfig) (Plan, error)
	Activate(RuntimeConfig, RuntimeConfig) error
	Verify(RuntimeConfig) error
	Status(RuntimeConfig) ([]Status, error)
	Disconnect(Instance, uint32, string) error
	Logs(string) ([]string, error)
	Maintain(RuntimeConfig) error
}

func Ref(i Instance) string {
	b, _ := json.Marshal(i)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func Active(c RuntimeConfig) map[string]Instance {
	v := map[string]Instance{}
	for _, i := range c.Instances {
		if i.Enabled {
			v[i.Interface] = i
		}
	}
	return v
}
func ValidateInstance(i Instance) error {
	if !IDPattern.MatchString(i.ID) || !IDPattern.MatchString(i.CertificateID) || !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`).MatchString(i.Interface) || i.Interface == "lo" {
		return errors.New("нужны ID, сертификат и имя TUN-интерфейса до 15 символов")
	}
	if i.Name == "" || len(i.Name) > 100 {
		return errors.New("нужно название экземпляра до 100 символов")
	}
	if i.Mode != "server" && i.Mode != "client" || i.Protocol != "udp" && i.Protocol != "tcp" || i.Port < 1 || i.Port > 65535 {
		return errors.New("нужны режим server/client, udp/tcp и порт 1–65535")
	}
	a, e := netip.ParsePrefix(i.Address)
	if e != nil || !usableIPv4(a.Addr()) || a.Bits() < 16 || a.Bits() > 30 || a.Addr() == a.Masked().Addr() {
		return errors.New("адрес TUN: IPv4 с маской /16–/30, не адрес сети")
	}
	last := a.Masked().Addr().As4()
	for n := a.Bits(); n < 32; n++ {
		last[n/8] |= 1 << uint(7-n%8)
	}
	if a.Addr() == netip.AddrFrom4(last) {
		return errors.New("адрес TUN не может быть broadcast")
	}
	for _, r := range reservedIPv4 {
		if a.Masked().Overlaps(r) {
			return errors.New("подсеть TUN пересекается со служебными адресами")
		}
	}
	// Reuse the strict structured route validator; no arbitrary directives.
	p := Profile{ID: i.ID, Name: i.Name, ServerCertificateID: i.CertificateID, ClientCertificateID: i.CertificateID, Remote: "vpn.example.org", Port: i.Port, Protocol: i.Protocol, Routes: i.Routes}
	if e = ValidateProfile(p); e != nil {
		return e
	}
	if i.Mode == "server" {
		if i.Auth != nil {
			if err := i.Auth.Validate(); err != nil {
				return err
			}
		}
		if i.PublicEndpoint != "" && !ValidRemote(i.PublicEndpoint) {
			return errors.New("некорректный публичный адрес OpenVPN")
		}
		p.Routes = i.ClientRoutes
		if e = ValidateProfile(p); e != nil {
			return e
		}
		bind, e := netip.ParseAddr(i.BindAddress)
		if e != nil || !usableIPv4(bind) || i.Remote != "" || i.ServerCertificateID != "" || len(i.Routes) > 0 {
			return errors.New("серверу нужен локальный IPv4 bind; дополнительные маршруты задаются на клиентах")
		}
		if len(i.Clients) > 256 {
			return errors.New("не более 256 клиентов на сервер")
		}
		seen := map[string]bool{}
		usernames := map[string]bool{}
		ips := map[string]bool{}
		for _, c := range i.Clients {
			ip, e := netip.ParseAddr(c.Address)
			cert := i.Auth == nil || i.Auth.Certificate
			if c.Username != "" || i.Auth != nil && i.Auth.Credentials() {
				if !identity.Username.MatchString(c.Username) || c.Username == "default" || usernames[c.Username] {
					return errors.New("клиентам нужны уникальные логины")
				}
				usernames[c.Username] = true
			}
			if e != nil || !usableIPv4(ip) || !a.Contains(ip) || ip == a.Addr() || ip == a.Masked().Addr() || ip == netip.AddrFrom4(last) ||
				cert && (!IDPattern.MatchString(c.CertificateID) || seen[c.CertificateID]) || !cert && c.CertificateID != "" || ips[c.Address] {
				return errors.New("клиентам нужны разные сертификаты и свободные IPv4-адреса из подсети TUN")
			}
			seen[c.CertificateID] = true
			ips[c.Address] = true
		}
	} else {
		remote, e := netip.ParseAddr(i.Remote)
		if i.Auth != nil || i.PublicEndpoint != "" || len(i.ClientRoutes) > 0 || e != nil || !usableIPv4(remote) || !IDPattern.MatchString(i.ServerCertificateID) || i.BindAddress != "" || len(i.Clients) > 0 {
			return errors.New("клиенту нужны числовой IPv4 сервера и его сертификат; bind и список клиентов не задаются")
		}
		if a.Contains(remote) {
			return errors.New("адрес VPN-сервера попадает в подсеть TUN")
		}
		for _, s := range i.Routes {
			r, _ := netip.ParsePrefix(s)
			if r.Contains(remote) {
				return errors.New("маршрут VPN захватывает адрес его сервера")
			}
		}
	}
	return nil
}
func ValidateRuntime(c RuntimeConfig) error {
	if len(c.Instances) > 4 {
		return errors.New("не более 4 экземпляров OpenVPN")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for n, i := range c.Instances {
		if e := ValidateInstance(i); e != nil {
			return fmt.Errorf("%s: %w", i.Name, e)
		}
		if ids[i.ID] || names[i.Interface] {
			return errors.New("ID и имя TUN должны быть уникальны")
		}
		ids[i.ID] = true
		names[i.Interface] = true
		if !i.Enabled {
			continue
		}
		a, _ := netip.ParsePrefix(i.Address)
		for _, j := range c.Instances[:n] {
			if !j.Enabled {
				continue
			}
			b, _ := netip.ParsePrefix(j.Address)
			if a.Overlaps(b) {
				return errors.New("подсети экземпляров OpenVPN пересекаются")
			}
			if i.Mode == "server" && j.Mode == "server" && i.Port == j.Port && i.Protocol == j.Protocol && i.BindAddress == j.BindAddress {
				return errors.New("порт OpenVPN уже занят другим экземпляром")
			}
		}
	}
	return nil
}
func PreviewRuntime(c RuntimeConfig) Plan {
	p := Plan{Actions: []string{}, Warnings: []string{"Изменения требуют подтверждения. При тайм-ауте восстановятся предыдущие экземпляры.", "Откат не отменяет отзыв сертификатов и не понижает номер CRL.", "Применение и обновление CRL перезапускают соединения. Правила доступа VPN задаются в разделе firewall; LAN остаётся защищён."}}
	for _, i := range c.Instances {
		p.Actions = append(p.Actions, fmt.Sprintf("%s: %s · %s · %s", i.Name, i.Mode, i.Interface, i.Address))
	}
	return p
}

func parseSessions(raw string) []Session {
	out := []Session{}
	columns := map[string]int{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) > 2 && fields[0] == "HEADER" && fields[1] == "CLIENT_LIST" {
			for n, name := range fields[2:] {
				columns[name] = n + 1
			}
		}
		if len(fields) < 2 || fields[0] != "CLIENT_LIST" {
			continue
		}
		get := func(name string) string {
			n, ok := columns[name]
			if !ok || n >= len(fields) {
				return ""
			}
			return fields[n]
		}
		rx, _ := strconv.ParseUint(get("Bytes Received"), 10, 64)
		tx, _ := strconv.ParseUint(get("Bytes Sent"), 10, 64)
		username := get("Username")
		if username == "UNDEF" {
			username = ""
		}
		var clientID *uint32
		if id, err := strconv.ParseUint(get("Client ID"), 10, 32); err == nil {
			value := uint32(id)
			clientID = &value
		}
		out = append(out, Session{ClientID: clientID, Name: get("Common Name"), Username: username, Address: get("Virtual Address"), Remote: get("Real Address"), RXBytes: rx, TXBytes: tx})
	}
	return out
}
