package services

import "testing"

func validConfig() Config {
	c := Default()
	c.DHCP.Enabled = true
	c.DHCP.Pools = []Pool{{ID: "office", Name: "Office", Interface: "br-lan", Address: "192.0.2.1", Network: "192.0.2.0/24", Start: "192.0.2.100", End: "192.0.2.200", Gateway: "192.0.2.1", DNS: []string{"192.0.2.1"}, Reservations: []Reservation{{MAC: "02:11:22:33:44:55", IP: "192.0.2.20", Hostname: "printer"}}}}
	return c
}
func TestDHCPValidation(t *testing.T) {
	if e := Validate(validConfig()); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Config){
		"server in pool":        func(c *Config) { c.DHCP.Pools[0].Address = "192.0.2.120" },
		"broadcast":             func(c *Config) { c.DHCP.Pools[0].End = "192.0.2.255" },
		"network address":       func(c *Config) { c.DHCP.Pools[0].Start = "192.0.2.0" },
		"outside reservation":   func(c *Config) { c.DHCP.Pools[0].Reservations[0].IP = "198.51.100.20" },
		"duplicate reservation": func(c *Config) { p := &c.DHCP.Pools[0]; p.Reservations = append(p.Reservations, p.Reservations[0]) },
		"multicast mac":         func(c *Config) { c.DHCP.Pools[0].Reservations[0].MAC = "01:11:22:33:44:55" },
		"duplicate interface":   func(c *Config) { p := c.DHCP.Pools[0]; p.ID = "other"; c.DHCP.Pools = append(c.DHCP.Pools, p) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			mutate(&c)
			if Validate(c) == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}
func TestDNSValidationAndEngine(t *testing.T) {
	c := Default()
	c.DNS.Enabled = true
	c.DNS.Interface = "br-lan"
	c.DNS.Address = "192.0.2.1"
	c.DNS.AllowedClients = []string{"192.0.2.0/24"}
	if e := Validate(c); e != nil {
		t.Fatal(e)
	}
	c.DNS.AllowedClients = nil
	if Validate(c) == nil {
		t.Fatal("open resolver without explicit ACL")
	}
	c.DNS.AllowedClients = []string{"192.0.2.0/24"}
	c.DNS.Zones = []Zone{{Name: "home.arpa.", Records: []string{"not a DNS record"}}}
	if Validate(c) == nil {
		t.Fatal("bad zone accepted")
	}
}
