package netconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func topology() Config {
	return Config{Interfaces: []Link{
		{Name: "p1", Type: "physical", MTU: 1500, Up: true, Addresses: []string{}, Members: []string{}},
		{Name: "p2", Type: "physical", MTU: 1500, Up: true, Addresses: []string{}, Members: []string{}},
		{Name: "bond0", Type: "bond", MTU: 1500, Up: true, BondMode: "active-backup", Members: []string{"p1", "p2"}, Addresses: []string{}},
		{Name: "v100", Type: "vlan", MTU: 1500, Up: true, Parent: "bond0", VLAN: 100, Addresses: []string{}, Members: []string{}},
		{Name: "br100", Type: "bridge", MTU: 1500, Up: true, Members: []string{"v100"}, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
	}, Routes: []Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.254", Interface: "br100", Metric: 100}}}
}
func TestTopologyAndEtcnetRendering(t *testing.T) {
	c := topology()
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	order, err := Order(c.Interfaces)
	if err != nil || order[2].Name != "bond0" || order[4].Name != "br100" {
		t.Fatal("wrong dependency order", order, err)
	}
	files := Render(c)
	if !strings.Contains(files["v100"]["options"], "HOST='bond0'\nVID=100") || !strings.Contains(files["bond0"]["options"], "BONDMODE=1") || !strings.Contains(files["br100"]["ipv4route"], "metric 100 proto 186") {
		t.Fatal(files)
	}
	if !strings.Contains(files["br100"]["sysctl.conf"], "accept_ra=0") {
		t.Fatal("static IPv6 not persisted")
	}
}

func TestIPv6LinkLocalGatewayAndInactiveBridge(t *testing.T) {
	c := topology()
	c.Routes = []Route{{Destination: "::/0", Gateway: "fe80::1", Interface: "br100", Metric: 100}}
	if err := Validate(c); err != nil {
		t.Fatal("IPv6 link-local next hop rejected", err)
	}
	c.Routes = []Route{}
	c.Interfaces[4].Up = false
	if err := Validate(c); err != nil {
		t.Fatal("inactive bridge rejected", err)
	}
}
func TestRejectUnsafeAndConflictingTopology(t *testing.T) {
	cases := map[string]func(*Config){
		"path":            func(c *Config) { c.Interfaces[0].Name = "../bad" },
		"shell":           func(c *Config) { c.Interfaces[3].Parent = "p1';true" },
		"cycle":           func(c *Config) { c.Interfaces[3].Parent = "br100" },
		"member IP":       func(c *Config) { c.Interfaces[0].Addresses = []string{"10.0.0.1/24"} },
		"duplicate port":  func(c *Config) { c.Interfaces[4].Members = append(c.Interfaces[4].Members, "p1") },
		"missing member":  func(c *Config) { c.Interfaces[2].Members[0] = "unknown" },
		"vlan":            func(c *Config) { c.Interfaces[3].VLAN = 4095 },
		"bond mode":       func(c *Config) { c.Interfaces[2].BondMode = "balance-rr" },
		"bad gateway":     func(c *Config) { c.Routes[0].Gateway = "10.99.0.1" },
		"family":          func(c *Config) { c.Routes[0].Gateway = "2001:db8::fe" },
		"route on slave":  func(c *Config) { c.Routes[0].Interface = "v100" },
		"duplicate route": func(c *Config) { c.Routes = append(c.Routes, c.Routes[0]) },
		"overlap": func(c *Config) {
			c.Interfaces = append(c.Interfaces, Link{Name: "other", Type: "physical", Up: true, MTU: 1500, Addresses: []string{"192.0.2.10/24"}})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := topology()
			mutate(&c)
			if Validate(c) == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}
func TestEtcnetBackupRestoreAndSymlinkRejection(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "p1")
	if err := os.Mkdir(p, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "options"), []byte("TYPE=eth\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := readDirectory(root, "p1")
	if err != nil {
		t.Fatal(err)
	}
	target := renderDirectories(topology())["p1"]
	if err = writeDirectory(root, "p1", target); err != nil {
		t.Fatal(err)
	}
	if err = writeDirectory(root, "p1", before); err != nil {
		t.Fatal(err)
	}
	actual, err := readDirectory(root, "p1")
	if err != nil || len(actual.Files) != 1 || actual.Files["options"] != before.Files["options"] {
		t.Fatal("original file data/mode not restored", actual, err)
	}
	if err = os.Symlink(p, filepath.Join(root, "bad")); err != nil {
		t.Fatal(err)
	}
	if _, err = readDirectory(root, "bad"); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err = os.WriteFile(filepath.Join(p, "ifup-post"), []byte("echo dangerous"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readDirectory(root, "p1"); err == nil {
		t.Fatal("hook file silently overwritten")
	}
}
