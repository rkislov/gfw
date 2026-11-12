package policy

import (
	"strings"
	"testing"
)

func advanced() Config {
	c := Default()
	c.Zones = []Zone{{ID: "lan", Name: "LAN", Kind: "lan", Interfaces: []string{"lan0"}}, {ID: "wan", Name: "WAN", Kind: "wan", Interfaces: []string{"wan0"}}}
	c.AddressGroups = []AddressGroup{{ID: "clients", Name: "Clients", Family: "ipv4", Networks: []string{"192.0.2.0/24", "192.0.2.1/32"}}}
	c.ServiceGroups = []ServiceGroup{{ID: "dns", Name: "DNS", Protocol: "tcp_udp", Ports: []string{"53", "8000-8100", "8050-8200"}}}
	c.Rules = []Rule{{ID: "allow-dns", Name: "DNS", Chain: "forward", Family: "ipv4", Protocol: "any", Action: "accept", Enabled: true, SourceZone: "lan", DestinationZone: "wan", SourceGroup: "clients", Service: "dns"}}
	return c
}
func TestObjectsCompileToTypedSetsAndStatefulReplies(t *testing.T) {
	c := advanced()
	text, err := CompileManaged(c, Safety{LANInterface: "lan0", ManagementPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type ifname", "type ipv4_addr", "type inet_service", "8000-8200", "tcp dport @", "udp dport @", "ct direction original", "ct direction reply", "ct label set", "gfw:anti-lockout"} {
		if !strings.Contains(text, want) {
			t.Fatal("missing", want, text)
		}
	}
	if strings.Contains(text, "192.0.2.1/32") || strings.Contains(text, "ct mark set") {
		t.Fatal("overlap or foreign connmark modification")
	}
	if strings.Index(text, "gfw:anti-lockout") > strings.Index(text, "gfw:state-reply") {
		t.Fatal("stateful rules precede management protection")
	}
}
func TestObjectReferencesAndUnsafeValuesRejected(t *testing.T) {
	cases := map[string]func(*Config){
		"delete group":        func(c *Config) { c.AddressGroups = nil },
		"delete zone":         func(c *Config) { c.Zones = c.Zones[:1] },
		"duplicate interface": func(c *Config) { c.Zones[1].Interfaces = []string{"lan0"} },
		"unsafe interface":    func(c *Config) { c.Zones[1].Interfaces = []string{"wan0;flush"} },
		"empty active zone":   func(c *Config) { c.Zones[1].Interfaces = nil },
		"family mismatch":     func(c *Config) { c.Rules[0].Family = "ipv6" },
		"service conflict":    func(c *Config) { c.Rules[0].Protocol = "tcp" },
		"unsafe ports":        func(c *Config) { c.ServiceGroups[0].Ports = []string{"53;accept"} },
		"bad port range":      func(c *Config) { c.ServiceGroups[0].Ports = []string{"9000-8000"} },
		"host bits":           func(c *Config) { c.AddressGroups[0].Networks = []string{"192.0.2.1/24"} },
		"unknown service":     func(c *Config) { c.Rules[0].Service = "deleted" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := advanced()
			mutate(&c)
			if _, err := Compile(c); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}
func TestDNATHairpinAndManagementProtection(t *testing.T) {
	c := advanced()
	c.NAT = []NAT{{ID: "web", Name: "Public web", Type: "dnat", Enabled: true, SourceZone: "wan", DestinationZone: "lan", Protocol: "tcp", Destination: "198.51.100.1/32", DestinationPort: 8088, TranslatedAddress: "192.0.2.10", TranslatedPort: 80, AllowForward: true, Hairpin: true}}
	text, err := CompileManaged(c, Safety{LANInterface: "lan0", ManagementPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dnat ip to 192.0.2.10:80", "ct original proto-dst 8088", "ct original ip daddr 198.51.100.1/32", "gfw:hairpin-snat:web", "gfw:nat-forward:web", "gfw:nat-anti-lockout"} {
		if !strings.Contains(text, want) {
			t.Fatal("missing", want)
		}
	}
	c.NAT[0].DestinationPort = 8443
	if _, err = CompileManaged(c, Safety{LANInterface: "lan0", ManagementPort: 8443}); err == nil {
		t.Fatal("NAT hijacks management port")
	}
	c.NAT[0].DestinationPort = 8088
	c.Stateful = false
	if Validate(c) == nil {
		t.Fatal("auto-forward without stateful")
	}
	c.Stateful = true
	c.NAT[0].TranslatedAddress = "2001:db8::1"
	if Validate(c) == nil {
		t.Fatal("IPv6 NAT accepted")
	}
}
func TestLegacyConfigDoesNotEnableNewStatefulBehavior(t *testing.T) {
	c := Canonical(Config{DefaultInput: "drop", DefaultForward: "drop", Rules: []Rule{}})
	if c.Stateful || c.Zones == nil {
		t.Fatal("legacy policy changed")
	}
	text, err := Compile(c)
	if err != nil || strings.Contains(text, "ct direction reply") {
		t.Fatal(text, err)
	}
}
