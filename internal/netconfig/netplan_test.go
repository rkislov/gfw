package netconfig

import (
	"strings"
	"testing"
)

func TestRenderNetplanStaticTopology(t *testing.T) {
	c := Config{
		Interfaces: []Link{
			{Name: "port1", Type: "physical", MTU: 1500, Up: true},
			{Name: "port2", Type: "physical", MTU: 1500, Up: true},
			{Name: "bond0", Type: "bond", MTU: 1500, Up: true, Members: []string{"port1", "port2"}, BondMode: "802.3ad"},
			{Name: "vlan20", Type: "vlan", MTU: 1500, Up: true, Parent: "bond0", VLAN: 20, Addresses: []string{"2001:db8:20::1/64"}},
			{Name: "br-test", Type: "bridge", MTU: 1500},
		},
		Routes: []Route{{Destination: "2001:db8:21::/64", Interface: "vlan20", Metric: 50}},
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	got, err := renderNetplan(c)
	if err != nil || got == nil || got.Mode != 0600 {
		t.Fatal(got, err)
	}
	for _, token := range []string{"renderer: networkd", "mode: 802.3ad", "id: 20", "link: bond0", "scope: link", `activation-mode: "off"`} {
		if !strings.Contains(got.Body, token) {
			t.Errorf("missing %q in:\n%s", token, got.Body)
		}
	}
}

func TestNetplanRejectsChangesToForeignUnits(t *testing.T) {
	base := map[string]File{"10-netplan-lan0.network": {Body: "original LAN"}}
	c := Config{Interfaces: []Link{{Name: "port1", Type: "physical"}}}
	combined := map[string]File{
		"10-netplan-lan0.network":  base["10-netplan-lan0.network"],
		"10-netplan-port1.network": {Body: "managed port"},
		"10-netplan-port1.link":    {Body: "managed MTU"},
	}
	if units, err := ownedUnits(base, combined, c); err != nil || len(units) != 2 {
		t.Fatalf("independent config rejected: %+v, %v", units, err)
	}
	combined["10-netplan-lan0.network"] = File{Body: "modified LAN"}
	if _, err := ownedUnits(base, combined, c); err == nil {
		t.Fatal("accepted a change to the LAN profile")
	}
	combined["10-netplan-lan0.network"] = base["10-netplan-lan0.network"]
	combined["50-other.network"] = File{Body: "unexpected"}
	if _, err := ownedUnits(base, combined, c); err == nil {
		t.Fatal("accepted an unexpected generated file")
	}
}
