package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rkislov/gfw/internal/traffic"
)

func symbol(kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return kind + "_" + hex.EncodeToString(sum[:8])
}
func generation(c Config, s *Safety) string {
	raw, _ := json.Marshal(struct {
		Config Config
		Safety *Safety
	}{c, s})
	sum := sha256.Sum256(raw)
	return "0x4746" + hex.EncodeToString(sum[:6])
}
func labelMask(first, last int) string {
	xs := []string{}
	for i := first; i <= last; i++ {
		xs = append(xs, strconv.Itoa(i))
	}
	return "(" + strings.Join(xs, " | ") + ")"
}
func labelValue(tag string) string {
	v, _ := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64)
	xs := []string{}
	for i := 0; i < 64; i++ {
		if v&(uint64(1)<<i) != 0 {
			xs = append(xs, strconv.Itoa(i))
		}
	}
	return "(" + strings.Join(xs, " | ") + ")"
}
func stamp(tag string) string {
	return "ct label set (ct label & " + labelMask(64, 127) + ") | " + labelValue(tag)
}

func prefixes(g AddressGroup) []string {
	xs := []netip.Prefix{}
	for _, n := range g.Networks {
		p, _ := netip.ParsePrefix(n)
		xs = append(xs, p)
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].Bits() != xs[j].Bits() {
			return xs[i].Bits() < xs[j].Bits()
		}
		return xs[i].Addr().Less(xs[j].Addr())
	})
	kept := []netip.Prefix{}
	for _, p := range xs {
		covered := false
		for _, q := range kept {
			if q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	out := []string{}
	for _, p := range kept {
		out = append(out, p.String())
	}
	return out
}
func emitSets(b *strings.Builder, c Config) {
	for _, z := range c.Zones {
		fmt.Fprintf(b, "  set %s {\n    type ifname\n", symbol("zone", z.ID))
		if len(z.Interfaces) > 0 {
			xs := []string{}
			for _, n := range z.Interfaces {
				xs = append(xs, strconv.Quote(n))
			}
			fmt.Fprintf(b, "    elements = { %s }\n", strings.Join(xs, ", "))
		}
		b.WriteString("  }\n")
	}
	for _, g := range c.AddressGroups {
		typ := "ipv4_addr"
		if g.Family == "ipv6" {
			typ = "ipv6_addr"
		}
		fmt.Fprintf(b, "  set %s {\n    type %s\n    flags interval\n    elements = { %s }\n  }\n", symbol("addr", g.ID), typ, strings.Join(prefixes(g), ", "))
	}
	for _, g := range c.ServiceGroups {
		fmt.Fprintf(b, "  set %s {\n    type inet_service\n    flags interval\n    elements = { %s }\n  }\n", symbol("svc", g.ID), strings.Join(servicePorts(g), ", "))
	}
}
func zoneMatch(direction, id string) string {
	if id == "" {
		return ""
	}
	return direction + " @" + symbol("zone", id)
}
func add(parts *[]string, s string) {
	if s != "" {
		*parts = append(*parts, s)
	}
}
func protocols(g ServiceGroup) []string {
	if g.Protocol == "tcp_udp" {
		return []string{"tcp", "udp"}
	}
	return []string{g.Protocol}
}
func ruleLines(c Config, r Rule, tag string, revision *int64) []string {
	f, _ := groupFamily(c, r)
	ps := []string{r.Protocol}
	if r.Service != "" {
		for _, g := range c.ServiceGroups {
			if g.ID == r.Service {
				ps = protocols(g)
			}
		}
	}
	out := []string{}
	for _, proto := range ps {
		p := []string{}
		ip := "ip"
		if f == "ipv6" {
			ip = "ip6"
		}
		if f != "any" {
			p = append(p, "meta nfproto "+f)
		}
		add(&p, zoneMatch("iifname", r.SourceZone))
		add(&p, zoneMatch("oifname", r.DestinationZone))
		if r.Source != "" {
			p = append(p, ip+" saddr "+r.Source)
		}
		if r.Destination != "" {
			p = append(p, ip+" daddr "+r.Destination)
		}
		if r.SourceGroup != "" {
			p = append(p, ip+" saddr @"+symbol("addr", r.SourceGroup))
		}
		if r.DestinationGroup != "" {
			p = append(p, ip+" daddr @"+symbol("addr", r.DestinationGroup))
		}
		if proto != "any" {
			v := proto
			if v == "icmpv6" {
				v = "ipv6-icmp"
			}
			p = append(p, "meta l4proto "+v)
		}
		if r.Service != "" {
			p = append(p, proto+" dport @"+symbol("svc", r.Service))
		} else if r.DestinationPort != 0 {
			p = append(p, proto+" dport "+strconv.Itoa(r.DestinationPort))
		}
		if c.Stateful && r.Action == "accept" && proto == "icmpv6" {
			nd := append([]string{}, p...)
			nd = append(nd, "ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }")
			if revision != nil {
				out = append(out, logRule(strings.Join(nd, " "), *revision, r.Chain, r.Action, r.ID))
			}
			nd = append(nd, "counter accept comment "+strconv.Quote("gfw:nd:"+r.ID))
			out = append(out, strings.Join(nd, " "))
		}
		if c.Stateful && r.Action == "accept" {
			p = append(p, "ct direction original ct state { new, established, related }")
		}
		if revision != nil {
			out = append(out, logRule(strings.Join(p, " "), *revision, r.Chain, r.Action, r.ID))
		}
		if c.Stateful && r.Action == "accept" {
			ruleTag := tag
			if c.Flowtable != nil && r.FastPath && !r.LogRequired {
				ruleTag = fastGeneration(tag)
			}
			p = append(p, stamp(ruleTag))
		}
		p = append(p, "counter", r.Action, strconv.Quote("gfw:"+r.ID))
		p[len(p)-1] = "comment " + p[len(p)-1]
		out = append(out, strings.Join(p, " "))
	}
	return out
}
func systemRules(b *strings.Builder, chain string, s *Safety) {
	if s == nil || chain == "forward" {
		return
	}
	direction, port := "iifname", "dport"
	suffix := ""
	if chain == "output" {
		direction = "oifname"
		port = "sport"
		suffix = "-reply"
	}
	fmt.Fprintf(b, "    %s \"lo\" counter accept comment \"gfw:system-loopback\"\n", direction)
	fmt.Fprintf(b, "    %s %q tcp %s %d counter accept comment \"gfw:anti-lockout%s\"\n", direction, s.LANInterface, port, s.ManagementPort, suffix)
	fmt.Fprintf(b, "    %s %q meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, packet-too-big, destination-unreachable, time-exceeded, parameter-problem } counter accept comment \"gfw:management-ipv6%s\"\n", direction, s.LANInterface, suffix)
}
func natMatch(n NAT, incoming, output bool) []string {
	p := []string{"meta nfproto ipv4"}
	if incoming {
		add(&p, zoneMatch("iifname", n.SourceZone))
	}
	if output {
		add(&p, zoneMatch("oifname", n.DestinationZone))
	}
	if n.Source != "" {
		p = append(p, "ip saddr "+n.Source)
	}
	if n.Destination != "" {
		p = append(p, "ip daddr "+n.Destination)
	}
	if n.Protocol != "any" {
		p = append(p, "meta l4proto "+n.Protocol)
	}
	if n.DestinationPort != 0 {
		p = append(p, n.Protocol+" dport "+strconv.Itoa(n.DestinationPort))
	}
	return p
}
func original(n NAT) string {
	out := "ct status dnat ct original proto-dst " + strconv.Itoa(n.DestinationPort)
	if n.Destination != "" {
		out += " ct original ip daddr " + n.Destination
	}
	return out
}
func translatedMatch(n NAT, incoming string) []string {
	p := []string{"meta nfproto ipv4", zoneMatch("iifname", incoming), zoneMatch("oifname", n.DestinationZone), "ip daddr " + n.TranslatedAddress, "meta l4proto " + n.Protocol, n.Protocol + " dport " + strconv.Itoa(n.TranslatedPort), original(n)}
	if n.Source != "" {
		p = append(p, "ip saddr "+n.Source)
	}
	return p
}
func natForwards(b *strings.Builder, c Config, tag string, revision *int64) {
	for _, n := range c.NAT {
		if !n.Enabled || n.Type != "dnat" || !n.AllowForward {
			continue
		}
		zones := []string{n.SourceZone}
		if n.Hairpin {
			zones = append(zones, n.DestinationZone)
		}
		for _, in := range zones {
			p := translatedMatch(n, in)
			p = append(p, "ct direction original ct state { new, established, related }")
			if revision != nil {
				fmt.Fprintln(b, "   ", logRule(strings.Join(p, " "), *revision, "forward", "accept", "@nat-"+n.ID))
			}
			p = append(p, stamp(tag), "counter accept comment "+strconv.Quote("gfw:nat-forward:"+n.ID))
			fmt.Fprintf(b, "    %s\n", strings.Join(p, " "))
		}
	}
}
func emitNAT(b *strings.Builder, c Config, s *Safety) {
	enabled := false
	for _, n := range c.NAT {
		enabled = enabled || n.Enabled
	}
	if !enabled {
		return
	}
	b.WriteString("  chain nat_in {\n    type nat hook prerouting priority -100; policy accept;\n")
	if s != nil {
		fmt.Fprintf(b, "    iifname %q tcp dport %d return comment \"gfw:nat-anti-lockout\"\n", s.LANInterface, s.ManagementPort)
	}
	for _, n := range c.NAT {
		if !n.Enabled || n.Type != "dnat" {
			continue
		}
		p := natMatch(n, true, false)
		p = append(p, "counter dnat ip to "+n.TranslatedAddress+":"+strconv.Itoa(n.TranslatedPort), "comment "+strconv.Quote("gfw:nat:"+n.ID))
		fmt.Fprintf(b, "    %s\n", strings.Join(p, " "))
		if n.Hairpin {
			hair := n
			hair.SourceZone = n.DestinationZone
			p = natMatch(hair, true, false)
			p = append(p, "counter dnat ip to "+n.TranslatedAddress+":"+strconv.Itoa(n.TranslatedPort), "comment "+strconv.Quote("gfw:hairpin-dnat:"+n.ID))
			fmt.Fprintf(b, "    %s\n", strings.Join(p, " "))
		}
	}
	b.WriteString("  }\n  chain nat_out {\n    type nat hook postrouting priority 100; policy accept;\n")
	// Hairpin SNAT is restricted by the original DNAT tuple and internal target.
	for _, n := range c.NAT {
		if n.Enabled && n.Type == "dnat" && n.Hairpin {
			p := translatedMatch(n, n.DestinationZone)
			p = append(p, "counter masquerade comment "+strconv.Quote("gfw:hairpin-snat:"+n.ID))
			fmt.Fprintf(b, "    %s\n", strings.Join(p, " "))
		}
	}
	for _, n := range c.NAT {
		if !n.Enabled || n.Type == "dnat" {
			continue
		}
		p := natMatch(n, true, true)
		action := "masquerade"
		if n.Type == "snat" {
			action = "snat ip to " + n.TranslatedAddress
		}
		if n.Type == "no_snat" {
			action = "return"
		}
		p = append(p, "counter "+action, "comment "+strconv.Quote("gfw:nat:"+n.ID))
		fmt.Fprintf(b, "    %s\n", strings.Join(p, " "))
	}
	b.WriteString("  }\n")
}
func compile(c Config, safety *Safety, revision *int64) (string, error) {
	c = Canonical(c)
	if err := Validate(c); err != nil {
		return "", err
	}
	if safety != nil {
		if err := SafetyCheck(c, *safety); err != nil {
			return "", err
		}
	}
	tag := generation(c, safety)
	var b strings.Builder
	b.WriteString("# Generated GFW table; transactional application through gfw-agent only.\n# Reserve low 64 conntrack label bits for GFW; high bits are preserved.\n# Future IPS inspection must precede the stateful reply rule.\ntable inet gfw {\n  comment \"" + Owner + "\"\n")
	if revision != nil {
		fmt.Fprintf(&b, "  counter %s { }\n  counter %s { }\n", traffic.SeenCounter, traffic.LoggedCounter)
	}
	emitSets(&b, c)
	feedSets := emitFeedSets(&b, c.SecurityFeed)
	for _, chain := range []string{"input", "forward", "output"} {
		verdict := "drop"
		if chain == "output" {
			verdict = "accept"
		}
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority 0; policy %s;\n", chain, chain, verdict)
		systemRules(&b, chain, safety)
		if chain == "forward" {
			emitFeedRules(&b, feedSets, revision)
		}
		if c.Stateful {
			if revision != nil {
				fmt.Fprintln(&b, "   ", logRule("ct state invalid", *revision, chain, "drop", "@invalid"))
			}
			b.WriteString("    ct state invalid counter drop comment \"gfw:state-invalid\"\n")
			fmt.Fprintf(&b, "    ct direction reply ct state { established, related } ct label & %s == %s counter accept comment \"gfw:state-reply\"\n", labelMask(0, 63), labelValue(tag))
			if chain == "forward" && c.Flowtable != nil && c.FlowRuleCount() > 0 {
				fmt.Fprintf(&b, "    ct direction reply ct state { established, related } ct label & %s == %s counter accept comment \"gfw:flow-reply\"\n", labelMask(flowPairBits, 63), labelValue(fastGeneration(tag)))
			}
		}
		for _, r := range c.Rules {
			if r.Enabled && r.Chain == chain {
				for _, line := range ruleLines(c, r, tag, revision) {
					fmt.Fprintf(&b, "    %s\n", line)
				}
			}
		}
		if chain == "forward" {
			natForwards(&b, c, tag, revision)
		}
		if c.Stateful && chain == "output" {
			fmt.Fprintf(&b, "    ct direction original ct state { new, established, related } %s counter accept comment \"gfw:state-local-output\"\n", stamp(tag))
		}
		if revision != nil && verdict == "drop" {
			fmt.Fprintln(&b, "   ", logRule("", *revision, chain, "drop", "@default"))
		}
		b.WriteString("  }\n")
	}
	emitNAT(&b, c, safety)
	b.WriteString("}\n")
	return b.String(), nil
}

func logRule(match string, revision int64, direction, action, id string) string {
	prefix := fmt.Sprintf("gfw:%d:%s:%s:%s", revision, direction, action, id)
	return strings.TrimSpace(fmt.Sprintf("%s counter name %q limit rate 25/second burst 50 packets counter name %q log prefix %q group %d snaplen 128", match, traffic.SeenCounter, traffic.LoggedCounter, prefix, traffic.Group))
}
