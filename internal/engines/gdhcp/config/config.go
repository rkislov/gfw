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

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk YAML document.
type Config struct {
	Path         string         `yaml:"-" json:"-"`
	Server       Server         `yaml:"server" json:"server"`
	Database     Database       `yaml:"database" json:"database"`
	API          API            `yaml:"api" json:"api"`
	Web          Web            `yaml:"web" json:"web"`
	VLANs        []VLAN         `yaml:"vlans,omitempty" json:"vlans,omitempty"`
	Subnets      []Subnet       `yaml:"subnets,omitempty" json:"subnets,omitempty"`
	Reservations []Reservation  `yaml:"reservations,omitempty" json:"reservations,omitempty"`
	Relay        Relay          `yaml:"relay" json:"relay"`
	Options      map[int]string `yaml:"options,omitempty" json:"options,omitempty"`
	Classes      []Class        `yaml:"classes,omitempty" json:"classes,omitempty"`
	Logging      Logging        `yaml:"logging" json:"logging"`
	Metrics      Metrics        `yaml:"metrics" json:"metrics"`
	DHCPv6       DHCPv6         `yaml:"dhcpv6" json:"dhcpv6"`
	DDNS         DDNS           `yaml:"ddns" json:"ddns"`
	HA           HA             `yaml:"ha" json:"ha"`
}

type Server struct {
	// GFW supplies a socket-bound interface; do not infer a trunk VLAN from its name.
	BoundInterface string        `yaml:"-" json:"-"`
	Interfaces     []Interface   `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
	Authoritative  bool          `yaml:"authoritative" json:"authoritative"`
	PingCheck      bool          `yaml:"ping_check" json:"ping_check"`
	PingTimeout    time.Duration `yaml:"ping_timeout,omitempty" json:"ping_timeout,omitempty"`
	LeaseDefault   time.Duration `yaml:"lease_default" json:"lease_default"`
	LeaseMax       time.Duration `yaml:"lease_max" json:"lease_max"`
	OfferTTL       time.Duration `yaml:"offer_ttl,omitempty" json:"offer_ttl,omitempty"`
	DeclineHold    time.Duration `yaml:"decline_hold,omitempty" json:"decline_hold,omitempty"`
	Listen         string        `yaml:"listen,omitempty" json:"listen,omitempty"`
	ServerID       string        `yaml:"server_id,omitempty" json:"server_id,omitempty"`
	Hostname       string        `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	ManageLinks    bool          `yaml:"manage_links" json:"manage_links"`
	RawVLAN        bool          `yaml:"raw_vlan" json:"raw_vlan"`
}

type Interface struct {
	Name  string `yaml:"name" json:"name"`
	Mode  string `yaml:"mode,omitempty" json:"mode,omitempty"`
	VLANs []int  `yaml:"vlans,omitempty" json:"vlans,omitempty"`
	VLAN  int    `yaml:"vlan,omitempty" json:"vlan,omitempty"`
}

type Database struct {
	Driver string `yaml:"driver" json:"driver"`
	DSN    string `yaml:"dsn" json:"dsn"`
}

type API struct {
	Listen    string  `yaml:"listen" json:"listen"`
	TLS       TLS     `yaml:"tls" json:"tls"`
	Auth      Auth    `yaml:"auth" json:"auth"`
	RateLimit float64 `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	CORS      bool    `yaml:"cors" json:"cors"`
}

type TLS struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Cert    string `yaml:"cert,omitempty" json:"cert,omitempty"`
	Key     string `yaml:"key,omitempty" json:"key,omitempty"`
}

type Auth struct {
	LDAP       LDAP          `yaml:"ldap,omitempty" json:"ldap"`
	Groups     []AccessGroup `yaml:"groups,omitempty" json:"groups,omitempty"`
	JWTSecret  string        `yaml:"jwt_secret,omitempty" json:"jwt_secret,omitempty"`
	TokenTTL   time.Duration `yaml:"token_ttl,omitempty" json:"token_ttl,omitempty"`
	RefreshTTL time.Duration `yaml:"refresh_ttl,omitempty" json:"refresh_ttl,omitempty"`
	Users      []User        `yaml:"users,omitempty" json:"users,omitempty"`
	APIKeys    []APIKey      `yaml:"api_keys,omitempty" json:"api_keys,omitempty"`
}

type User struct {
	VLANIDs      []int    `yaml:"vlan_ids,omitempty" json:"vlan_ids,omitempty"`
	Groups       []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Username     string   `yaml:"username" json:"username"`
	PasswordHash string   `yaml:"password_hash" json:"password_hash,omitempty"`
	Role         string   `yaml:"role" json:"role"`
}

type APIKey struct {
	VLANIDs []int  `yaml:"vlan_ids,omitempty" json:"vlan_ids,omitempty"`
	Name    string `yaml:"name" json:"name"`
	Key     string `yaml:"key" json:"key,omitempty"`
	Role    string `yaml:"role" json:"role"`
}

type Web struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
}

type VLAN struct {
	ID        int            `yaml:"id" json:"id"`
	Name      string         `yaml:"name,omitempty" json:"name,omitempty"`
	Interface string         `yaml:"interface,omitempty" json:"interface,omitempty"`
	Priority  int            `yaml:"priority,omitempty" json:"priority,omitempty"`
	Source    string         `yaml:"source,omitempty" json:"source,omitempty"`
	SubnetRef string         `yaml:"subnet_ref,omitempty" json:"subnet_ref,omitempty"`
	Options   map[int]string `yaml:"options,omitempty" json:"options,omitempty"`
	Match     *VLANMatch     `yaml:"match,omitempty" json:"match,omitempty"`
}

type VLANMatch struct {
	CircuitIDParser string `yaml:"circuit_id_parser,omitempty" json:"circuit_id_parser,omitempty"`
	LinkSelection   string `yaml:"link_selection,omitempty" json:"link_selection,omitempty"`
}

type Subnet struct {
	ID           string         `yaml:"id" json:"id"`
	Network      string         `yaml:"network" json:"network"`
	Range        []string       `yaml:"range,omitempty" json:"range,omitempty"`
	Gateway      string         `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	DNS          []string       `yaml:"dns,omitempty" json:"dns,omitempty"`
	Domain       string         `yaml:"domain,omitempty" json:"domain,omitempty"`
	VLAN         *int           `yaml:"vlan,omitempty" json:"vlan,omitempty"`
	Options      map[int]string `yaml:"options,omitempty" json:"options,omitempty"`
	Reservations []Reservation  `yaml:"reservations,omitempty" json:"reservations,omitempty"`
	Lease        time.Duration  `yaml:"lease,omitempty" json:"lease,omitempty"`
	NextServer   string         `yaml:"next_server,omitempty" json:"next_server,omitempty"`
	BootFile     string         `yaml:"boot_file,omitempty" json:"boot_file,omitempty"`
	T1           time.Duration  `yaml:"t1,omitempty" json:"t1,omitempty"`
	T2           time.Duration  `yaml:"t2,omitempty" json:"t2,omitempty"`
}

type Reservation struct {
	MAC      string `yaml:"mac,omitempty" json:"mac,omitempty"`
	ClientID string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	IP       string `yaml:"ip" json:"ip"`
	Hostname string `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	SubnetID string `yaml:"subnet_id,omitempty" json:"subnet_id,omitempty"`
}

type Relay struct {
	Enabled            bool           `yaml:"enabled" json:"enabled"`
	TrustGIAddr        *bool          `yaml:"trust_giaddr,omitempty" json:"trust_giaddr,omitempty"`
	RequireOption82    bool           `yaml:"require_option_82" json:"require_option_82"`
	EchoOption82       *bool          `yaml:"echo_option_82,omitempty" json:"echo_option_82,omitempty"`
	MaxRelayHops       int            `yaml:"max_relay_hops,omitempty" json:"max_relay_hops,omitempty"`
	UnknownVLANAction  string         `yaml:"unknown_vlan_action,omitempty" json:"unknown_vlan_action,omitempty"`
	DefaultVLAN        *int           `yaml:"default_vlan,omitempty" json:"default_vlan,omitempty"`
	DefaultPool        string         `yaml:"default_pool,omitempty" json:"default_pool,omitempty"`
	VLANSourcePriority []string       `yaml:"vlan_source_priority,omitempty" json:"vlan_source_priority,omitempty"`
	CircuitIDParsers   []Parser       `yaml:"circuit_id_parsers,omitempty" json:"circuit_id_parsers,omitempty"`
	TrustedRelays      []TrustedRelay `yaml:"trusted_relays,omitempty" json:"trusted_relays,omitempty"`
}

type Parser struct {
	Name      string `yaml:"name" json:"name"`
	Regex     string `yaml:"regex" json:"regex"`
	VLANGroup string `yaml:"vlan_group,omitempty" json:"vlan_group,omitempty"`
}

type TrustedRelay struct {
	RemoteID string `yaml:"remote_id,omitempty" json:"remote_id,omitempty"`
	GIAddr   string `yaml:"giaddr,omitempty" json:"giaddr,omitempty"`
	Vendor   string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	VLAN     *int   `yaml:"vlan,omitempty" json:"vlan,omitempty"`
	SubnetID string `yaml:"subnet_id,omitempty" json:"subnet_id,omitempty"`
	Parser   string `yaml:"parser,omitempty" json:"parser,omitempty"`
}

type Class struct {
	Name        string `yaml:"name" json:"name"`
	VendorClass string `yaml:"vendor_class,omitempty" json:"vendor_class,omitempty"`
	OUI         string `yaml:"oui,omitempty" json:"oui,omitempty"`
	VLAN        *int   `yaml:"vlan,omitempty" json:"vlan,omitempty"`
	Subnet      string `yaml:"subnet,omitempty" json:"subnet,omitempty"`
}

type Logging struct {
	Level  string `yaml:"level,omitempty" json:"level,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
}

type Metrics struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen,omitempty" json:"listen,omitempty"`
}

type IPv6Pool struct {
	Interface string   `yaml:"interface" json:"interface"`
	Prefix    string   `yaml:"prefix" json:"prefix"`
	Start     string   `yaml:"start" json:"start"`
	End       string   `yaml:"end" json:"end"`
	Relays    []string `yaml:"relays,omitempty" json:"relays,omitempty"`
}

type DHCPv6 struct {
	Pools      []IPv6Pool `yaml:"pools,omitempty" json:"pools,omitempty"`
	DNS        []string   `yaml:"dns,omitempty" json:"dns,omitempty"`
	Preferred  uint32     `yaml:"preferred_seconds,omitempty" json:"preferred_seconds,omitempty"`
	Valid      uint32     `yaml:"valid_seconds,omitempty" json:"valid_seconds,omitempty"`
	Enabled    bool       `yaml:"enabled" json:"enabled"`
	Listen     string     `yaml:"listen,omitempty" json:"listen,omitempty"`
	ServerDUID string     `yaml:"server_duid,omitempty" json:"server_duid,omitempty"`
}

type DDNS struct {
	SambaVerify     *bool    `yaml:"samba_verify,omitempty" json:"samba_verify"`
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	Server          string   `yaml:"server,omitempty" json:"server,omitempty"`
	Zone            string   `yaml:"zone,omitempty" json:"zone,omitempty"`
	ReverseZone     string   `yaml:"reverse_zone,omitempty" json:"reverse_zone,omitempty"`
	TTL             uint32   `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	Hostname        *bool    `yaml:"hostname,omitempty" json:"hostname"`
	Principal       string   `yaml:"principal,omitempty" json:"principal,omitempty"`
	Keytab          string   `yaml:"keytab,omitempty" json:"keytab,omitempty"`
	Auth            string   `yaml:"auth,omitempty" json:"auth,omitempty"`
	KeyFile         string   `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	Port            int      `yaml:"port,omitempty" json:"port,omitempty"`
	ReverseZones    []string `yaml:"reverse_zones,omitempty" json:"reverse_zones,omitempty"`
	ProtectedNames  []string `yaml:"protected_names,omitempty" json:"protected_names,omitempty"`
	UpdateA         *bool    `yaml:"update_a,omitempty" json:"update_a"`
	UpdatePTR       *bool    `yaml:"update_ptr,omitempty" json:"update_ptr"`
	IntervalSeconds int      `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`
	TimeoutSeconds  int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

type HA struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Role    string        `yaml:"role,omitempty" json:"role,omitempty"`
	Peer    string        `yaml:"peer,omitempty" json:"peer,omitempty"`
	Secret  string        `yaml:"secret,omitempty" json:"secret,omitempty"`
	MCLT    time.Duration `yaml:"mclt,omitempty" json:"mclt,omitempty"`
	Split   int           `yaml:"split,omitempty" json:"split,omitempty"`
}

func (c *Config) EchoOption82() bool {
	if c.Relay.EchoOption82 == nil {
		return true
	}
	return *c.Relay.EchoOption82
}

func (c *Config) TrustGIAddr() bool {
	if c.Relay.TrustGIAddr == nil {
		return true
	}
	return *c.Relay.TrustGIAddr
}

// Load reads YAML, expands ${ENV} references, applies defaults and validates.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(raw, path)
}

// Parse decodes a YAML document that has already been read.
func Parse(raw []byte, path string) (*Config, error) {
	expanded := ExpandEnv(string(raw))
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("config: yaml: %w", err)
	}
	cfg.Path = path
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes the configuration atomically.
func Save(path string, cfg *Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	header := []byte("# Copyright 2026 Кислов Роман Сергеевич\n# Licensed under the Apache License, Version 2.0.\n")
	body := append(header, raw...)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ExpandEnv replaces ${VAR} and ${VAR:-default}. A doubled dollar ($$) yields one dollar.
func ExpandEnv(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteByte(s[i])
				continue
			}
			expr := s[i+2 : i+end]
			name := expr
			def := ""
			hasDef := false
			if idx := strings.Index(expr, ":-"); idx >= 0 {
				name = expr[:idx]
				def = expr[idx+2:]
				hasDef = true
			}
			if v, ok := os.LookupEnv(name); ok && name != "" {
				b.WriteString(v)
			} else if hasDef {
				b.WriteString(def)
			}
			i += end
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ApplyDefaults fills zero values that have a specified default.
func (c *Config) ApplyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = ":67"
	}
	if c.Server.LeaseDefault == 0 {
		c.Server.LeaseDefault = 24 * time.Hour
	}
	if c.Server.LeaseMax == 0 {
		c.Server.LeaseMax = 72 * time.Hour
	}
	if c.Server.OfferTTL == 0 {
		c.Server.OfferTTL = 60 * time.Second
	}
	if c.Server.DeclineHold == 0 {
		c.Server.DeclineHold = time.Hour
	}
	if c.Server.PingTimeout == 0 {
		c.Server.PingTimeout = 200 * time.Millisecond
	}
	if c.Server.ServerID == "" {
		for _, s := range c.Subnets {
			if s.Gateway != "" {
				c.Server.ServerID = s.Gateway
				break
			}
		}
	}
	if c.Database.Driver == "" {
		c.Database.Driver = "sqlite"
	}
	if c.Database.DSN == "" {
		c.Database.DSN = "/var/lib/godhcp/leases.db"
	}
	if c.API.Listen == "" {
		c.API.Listen = ":8181"
	}
	if c.API.Auth.TokenTTL == 0 {
		c.API.Auth.TokenTTL = time.Hour
	}
	if c.API.Auth.RefreshTTL == 0 {
		c.API.Auth.RefreshTTL = 24 * time.Hour
	}
	if c.API.RateLimit == 0 {
		c.API.RateLimit = 50
	}
	if c.Web.Path == "" {
		c.Web.Path = "/ui"
	}
	if c.Relay.MaxRelayHops == 0 {
		c.Relay.MaxRelayHops = 4
	}
	if c.Relay.UnknownVLANAction == "" {
		c.Relay.UnknownVLANAction = "ignore"
	}
	if len(c.Relay.VLANSourcePriority) == 0 {
		c.Relay.VLANSourcePriority = []string{
			"option82_sub5_link_selection",
			"option82_sub1_circuit_id",
			"giaddr",
			"default_vlan",
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Metrics.Listen == "" {
		c.Metrics.Listen = ":9090"
	}
	if c.DHCPv6.Enabled {
		if c.DHCPv6.Valid == 0 {
			c.DHCPv6.Valid = 7200
		}
		if c.DHCPv6.Preferred == 0 {
			c.DHCPv6.Preferred = c.DHCPv6.Valid / 2
		}
	}
	if c.DHCPv6.Listen == "" {
		c.DHCPv6.Listen = "[::]:547"
	}
	if c.DDNS.SambaVerify == nil {
		v := true
		c.DDNS.SambaVerify = &v
	}
	if c.DDNS.Auth == "" {
		c.DDNS.Auth = "gss-tsig"
	}
	if c.DDNS.Port == 0 {
		c.DDNS.Port = 53
	}
	if c.DDNS.IntervalSeconds == 0 {
		c.DDNS.IntervalSeconds = 30
	}
	if c.DDNS.TimeoutSeconds == 0 {
		c.DDNS.TimeoutSeconds = 10
	}
	if c.DDNS.Hostname == nil {
		v := true
		c.DDNS.Hostname = &v
	}
	if c.DDNS.UpdateA == nil {
		v := true
		c.DDNS.UpdateA = &v
	}
	if c.DDNS.UpdatePTR == nil {
		v := true
		c.DDNS.UpdatePTR = &v
	}
	if c.DDNS.TTL == 0 {
		c.DDNS.TTL = 300
	}
	if c.HA.Split == 0 {
		c.HA.Split = 128
	}
	if c.HA.MCLT == 0 {
		c.HA.MCLT = time.Hour
	}
	for i := range c.VLANs {
		if c.VLANs[i].Source == "" {
			c.VLANs[i].Source = "local"
		}
	}
	for i := range c.Subnets {
		if c.Subnets[i].VLAN == nil {
			for _, v := range c.VLANs {
				if v.SubnetRef == c.Subnets[i].ID {
					id := v.ID
					c.Subnets[i].VLAN = &id
					break
				}
			}
		}
		if c.Subnets[i].Lease == 0 {
			c.Subnets[i].Lease = c.Server.LeaseDefault
		}
	}
}

// AllReservations returns reservations nested in subnets and the top-level list.
func (c *Config) AllReservations() []Reservation {
	var out []Reservation
	for _, s := range c.Subnets {
		for _, r := range s.Reservations {
			if r.SubnetID == "" {
				r.SubnetID = s.ID
			}
			out = append(out, r)
		}
	}
	out = append(out, c.Reservations...)
	return out
}
