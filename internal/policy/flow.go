package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	FlowTableName = "gfw_flow"
	FlowOwner     = "gfw-flow-managed-v1"
	FlowBefore    = "gfw_flow_before"
	FlowAfter     = "gfw_flow_after"
	FlowTCP       = "gfw_flow_tcp"
	FlowUDP       = "gfw_flow_udp"
)

type FlowConfig struct {
	Interfaces []string `json:"interfaces"`
}

func (c Config) FlowRuleCount() int {
	count := 0
	for _, rule := range c.Rules {
		if rule.Enabled && rule.FastPath && !rule.LogRequired {
			count++
		}
	}
	return count
}

func flowRuleProtocol(c Config, r Rule) bool {
	if r.Service == "" {
		return r.Protocol == "tcp" || r.Protocol == "udp"
	}
	for _, service := range c.ServiceGroups {
		if service.ID == r.Service {
			return service.Protocol == "tcp" || service.Protocol == "udp" || service.Protocol == "tcp_udp"
		}
	}
	return false
}

func validateFlow(c Config) error {
	if c.Flowtable != nil {
		if !c.Stateful {
			return errors.New("ускорение транзита требует stateful-режима")
		}
		if len(c.Flowtable.Interfaces) < 2 || len(c.Flowtable.Interfaces) > 16 {
			return errors.New("для ускорения укажите от 2 до 16 интерфейсов")
		}
		zoned := map[string]bool{}
		for _, z := range c.Zones {
			if z.Kind == "vpn" || z.Kind == "management" {
				continue
			}
			for _, name := range z.Interfaces {
				zoned[name] = true
			}
		}
		seen := map[string]bool{}
		for _, name := range c.Flowtable.Interfaces {
			if !zoned[name] || seen[name] {
				return fmt.Errorf("интерфейс ускорения %q должен быть уникальным и входить в транзитную зону", name)
			}
			seen[name] = true
		}
	}
	for _, rule := range c.Rules {
		if !rule.FastPath {
			continue
		}
		if rule.LogRequired || rule.Chain != "forward" || rule.Action != "accept" || !flowRuleProtocol(c, rule) {
			return fmt.Errorf("ускорение правила %q доступно для разрешённого транзита TCP/UDP без обязательного журналирования", rule.Name)
		}
	}
	return nil
}

// The two generations share the already reserved low 64 conntrack label bits.
// Replacing either firewall policy or eligibility changes both generations.
const flowPairBits = 8

func fastGeneration(tag string) string { return "0x4747" + tag[len("0x4746"):len(tag)-2] + "00" }

// CompileFlow installs only the fast path. The regular filter decides which
// original flows may use it, and a later forward hook checks the reply.
func CompileFlow(c Config, s Safety, interfaces []string) string {
	if c.Flowtable == nil || c.FlowRuleCount() == 0 || len(interfaces) < 2 {
		return ""
	}
	c = Canonical(c)
	tag := fastGeneration(generation(c, &s))
	names := make([]string, 0, len(interfaces))
	for _, name := range interfaces {
		names = append(names, strconv.Quote(name))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n  comment %q\n", FlowTableName, FlowOwner)
	for _, name := range []string{FlowBefore, FlowAfter, FlowTCP, FlowUDP} {
		fmt.Fprintf(&b, "  counter %s { }\n", name)
	}
	fmt.Fprintf(&b, "  flowtable transit {\n    hook ingress priority -9; devices = { %s }; counter;\n  }\n", strings.Join(names, ", "))
	for i, name := range names {
		fmt.Fprintf(&b, "  chain ingress_before_%d {\n    type filter hook ingress device %s priority -10; policy accept;\n    counter name %q\n  }\n", i, name, FlowBefore)
		fmt.Fprintf(&b, "  chain ingress_after_%d {\n    type filter hook ingress device %s priority -8; policy accept;\n    counter name %q\n  }\n", i, name, FlowAfter)
	}
	// The low byte identifies the original ingress/egress pair. A reply
	// can enroll only on the exact reverse pair, including with asymmetric routes.
	fmt.Fprintf(&b, "  chain enroll {\n    type filter hook forward priority 300; policy accept;\n    ct label & %s != %s return\n",
		labelMask(flowPairBits, 63), labelValue(tag))
	b.WriteString("    meta l4proto { tcp, udp } ct direction original ct state { new, established } jump remember\n")
	b.WriteString("    ct direction reply ct state established jump reverse\n  }\n")
	b.WriteString("  chain remember {\n")
	for i, in := range c.Flowtable.Interfaces {
		for j, out := range c.Flowtable.Interfaces {
			if i == j || !slices.Contains(interfaces, in) || !slices.Contains(interfaces, out) {
				continue
			}
			pair := fmt.Sprintf("%s%02x", tag[:len(tag)-2], 16*i+j+1)
			fmt.Fprintf(&b, "    iifname %q oifname %q %s return\n", in, out, stamp(pair))
		}
	}
	b.WriteString("  }\n  chain reverse {\n")
	for i, in := range c.Flowtable.Interfaces {
		for j, out := range c.Flowtable.Interfaces {
			if i == j || !slices.Contains(interfaces, in) || !slices.Contains(interfaces, out) {
				continue
			}
			pair := fmt.Sprintf("%s%02x", tag[:len(tag)-2], 16*i+j+1)
			fmt.Fprintf(&b, "    iifname %q oifname %q ct label & %s == %s goto accelerate\n", out, in, labelMask(0, 63), labelValue(pair))
		}
	}
	fmt.Fprintf(&b, "  }\n  chain accelerate {\n    meta l4proto tcp flow add @transit counter name %q\n    meta l4proto udp flow add @transit counter name %q\n  }\n}\n", FlowTCP, FlowUDP)
	return b.String()
}

func canonicalFlow(c *FlowConfig) *FlowConfig {
	if c == nil {
		return nil
	}
	clone := &FlowConfig{Interfaces: slices.Clone(c.Interfaces)}
	slices.Sort(clone.Interfaces)
	return clone
}
