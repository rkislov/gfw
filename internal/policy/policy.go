// Package policy validates a deliberately small, explicit firewall model.
// Compilation never applies the resulting rules to the operating system.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/rkislov/gfw/internal/feed"
)

type Rule struct {
	FastPath         bool   `json:"fast_path,omitempty"`
	LogRequired      bool   `json:"log_required,omitempty"`
	SourceZone       string `json:"source_zone,omitempty"`
	DestinationZone  string `json:"destination_zone,omitempty"`
	SourceGroup      string `json:"source_group,omitempty"`
	DestinationGroup string `json:"destination_group,omitempty"`
	Service          string `json:"service,omitempty"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	Chain            string `json:"chain"`
	Family           string `json:"family"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	Protocol         string `json:"protocol"`
	DestinationPort  int    `json:"destination_port"`
	Action           string `json:"action"`
	Enabled          bool   `json:"enabled"`
}

type Config struct {
	Flowtable      *FlowConfig    `json:"flowtable,omitempty"`
	SecurityFeed   *feed.Filter   `json:"security_feed,omitempty"`
	Stateful       bool           `json:"stateful"`
	Zones          []Zone         `json:"zones"`
	AddressGroups  []AddressGroup `json:"address_groups"`
	ServiceGroups  []ServiceGroup `json:"service_groups"`
	NAT            []NAT          `json:"nat"`
	DefaultInput   string         `json:"default_input"`
	DefaultForward string         `json:"default_forward"`
	Rules          []Rule         `json:"rules"`
}

func Default() Config {
	return Config{DefaultInput: "drop", DefaultForward: "drop", Rules: []Rule{}, Stateful: true, Zones: []Zone{{ID: "lan", Name: "LAN", Kind: "lan", Interfaces: []string{}}, {ID: "wan", Name: "WAN", Kind: "wan", Interfaces: []string{}}, {ID: "dmz", Name: "DMZ", Kind: "dmz", Interfaces: []string{}}, {ID: "vpn", Name: "VPN", Kind: "vpn", Interfaces: []string{}}}, AddressGroups: []AddressGroup{}, ServiceGroups: []ServiceGroup{}, NAT: []NAT{}}
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func Validate(c Config) error {
	if err := c.SecurityFeed.Validate("ip"); err != nil {
		return err
	}
	if c.Rules == nil {
		return errors.New("rules должен быть JSON-массивом, в том числе пустым")
	}
	if c.DefaultInput != "drop" || c.DefaultForward != "drop" {
		return errors.New("базовая политика input/forward должна быть drop")
	}
	if len(c.Rules) > 10000 {
		return errors.New("не более 10000 правил")
	}
	ids := map[string]bool{}
	for i, r := range c.Rules {
		fail := func(s string) error { return fmt.Errorf("правило %d: %s", i+1, s) }
		if !identifier.MatchString(r.ID) || ids[r.ID] {
			return fail("нужен уникальный ID из букв, цифр, _ и -")
		}
		ids[r.ID] = true
		if len(r.Name) == 0 || len(r.Name) > 200 {
			return fail("имя должно содержать 1–200 байт")
		}
		if r.Chain != "input" && r.Chain != "forward" && r.Chain != "output" {
			return fail("неизвестное направление трафика")
		}
		if r.Family != "any" && r.Family != "ipv4" && r.Family != "ipv6" {
			return fail("неизвестное семейство")
		}
		if r.Protocol != "any" && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" && r.Protocol != "icmpv6" {
			return fail("неизвестный протокол")
		}
		if (r.Protocol == "icmp" && r.Family != "ipv4") || (r.Protocol == "icmpv6" && r.Family != "ipv6") {
			return fail("ICMP требует соответствующее семейство IP")
		}
		if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
			return fail("неизвестное действие")
		}
		if r.DestinationPort < 0 || r.DestinationPort > 65535 {
			return fail("порт должен быть в диапазоне 1–65535 или 0 (любой)")
		}
		if r.DestinationPort != 0 && r.Protocol != "tcp" && r.Protocol != "udp" {
			return fail("порт допустим только для TCP/UDP")
		}
		for _, s := range []string{r.Source, r.Destination} {
			if s == "" {
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fail("адрес должен быть IP/CIDR")
			}
			if r.Family == "any" {
				return fail("для IP/CIDR выберите семейство")
			}
			if (p.Addr().Is4() && r.Family != "ipv4") || (!p.Addr().Is4() && r.Family != "ipv6") {
				return fail("CIDR не соответствует семейству")
			}
			if p != p.Masked() {
				return fail("CIDR содержит биты хоста; укажите адрес сети")
			}
		}
	}
	if err := validateObjects(c); err != nil {
		return err
	}
	return validateFlow(c)
}

const Owner = "gfw-managed-v1"

type Safety struct {
	LANInterface   string `json:"lan_interface"`
	ManagementPort int    `json:"management_port"`
}

func (s Safety) Validate() error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(s.LANInterface) || s.ManagementPort < 1 || s.ManagementPort > 65535 {
		return errors.New("нужны LAN-интерфейс и порт управления 1–65535")
	}
	return nil
}

// Compile is an offline preview without a host's protected management rule.
func Compile(c Config) (string, error) {
	return compile(c, nil, nil)
}

// CompileManaged always inserts root-configured management protection before
// user rules. Neither a policy nor the web client can disable or reorder it.
func CompileManaged(c Config, safety Safety) (string, error) {
	if err := safety.Validate(); err != nil {
		return "", err
	}
	return compile(c, &safety, nil)
}

func CompileLogged(c Config, safety Safety, revision int64) (string, error) {
	if err := safety.Validate(); err != nil {
		return "", err
	}
	return compile(c, &safety, &revision)
}
