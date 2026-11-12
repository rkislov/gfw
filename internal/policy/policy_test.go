package policy

import (
	"strings"
	"testing"
)

func validRule() Rule {
	return Rule{ID: "dns_1", Name: "DNS", Chain: "forward", Family: "ipv4", Source: "192.168.1.0/24", Protocol: "udp", DestinationPort: 53, Action: "accept", Enabled: true}
}
func TestCompilePreservesOrderAndFamily(t *testing.T) {
	c := Default()
	c.Stateful = false
	a := validRule()
	b := a
	b.ID = "deny"
	b.Action = "drop"
	c.Rules = []Rule{a, b}
	out, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "meta nfproto ipv4 ip saddr 192.168.1.0/24 meta l4proto udp udp dport 53 counter accept") {
		t.Fatalf("wrong compile: %s", out)
	}
	if strings.Index(out, "gfw:dns_1") > strings.Index(out, "gfw:deny") {
		t.Fatal("rule order changed")
	}
	b.Enabled = false
	c.Rules = []Rule{b}
	out, err = Compile(c)
	if err != nil || strings.Contains(out, "gfw:deny") {
		t.Fatal("disabled rule emitted", err)
	}
}
func TestRejectUnsafeOrAmbiguousRules(t *testing.T) {
	cases := map[string]func(*Rule){
		"injected id":            func(r *Rule) { r.ID = "a\"; flush ruleset" },
		"injected chain":         func(r *Rule) { r.Chain = "forward; drop" },
		"injected address":       func(r *Rule) { r.Source = "192.0.2.0/24; accept" },
		"host bits":              func(r *Rule) { r.Source = "192.168.1.5/24" },
		"mixed family":           func(r *Rule) { r.Destination = "2001:db8::/32" },
		"port without transport": func(r *Rule) { r.Protocol = "any" },
		"invalid port":           func(r *Rule) { r.DestinationPort = 65536 },
		"ambiguous family":       func(r *Rule) { r.Family = "any" },
		"icmp family":            func(r *Rule) { r.Protocol = "icmpv6"; r.DestinationPort = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRule()
			mutate(&r)
			c := Default()
			c.Rules = []Rule{r}
			if _, err := Compile(c); err == nil {
				t.Fatal("unsafe rule accepted")
			}
		})
	}
	c := Default()
	r := validRule()
	c.Rules = []Rule{r, r}
	if Validate(c) == nil {
		t.Fatal("duplicate ids accepted")
	}
	c.Rules = nil
	if Validate(c) == nil {
		t.Fatal("null rules accepted")
	}
}
func TestIPv6ICMP(t *testing.T) {
	c := Default()
	c.Rules = []Rule{{ID: "nd", Name: "ICMPv6", Chain: "input", Family: "ipv6", Protocol: "icmpv6", Action: "accept", Enabled: true}}
	out, err := Compile(c)
	if err != nil || !strings.Contains(out, "meta l4proto ipv6-icmp") {
		t.Fatal(out, err)
	}
}

func TestProtectedLANRulePrecedesUserDeny(t *testing.T) {
	c := Default()
	r := validRule()
	r.Chain = "input"
	r.Action = "drop"
	c.Rules = []Rule{r}
	out, err := CompileManaged(c, Safety{LANInterface: "lan0", ManagementPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `iifname "lan0" tcp dport 8443 counter accept comment "gfw:anti-lockout"`) || strings.Index(out, "gfw:anti-lockout") > strings.Index(out, "gfw:dns_1") {
		t.Fatal("management rule is missing or can be shadowed", out)
	}
	if _, err = CompileManaged(c, Safety{LANInterface: `lan";flush`, ManagementPort: 8443}); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}
