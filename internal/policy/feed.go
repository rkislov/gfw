package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkislov/gfw/internal/feed"
)

type feedSet struct {
	match      string
	exceptions bool
}

func feedFamily(values []string, v4 bool) []string {
	var out []string
	for _, value := range values {
		p, _ := netip.ParsePrefix(value)
		if p.Addr().Is4() == v4 {
			out = append(out, value)
		}
	}
	return out
}

func emitFeedSets(b *strings.Builder, f *feed.Filter) []feedSet {
	if f == nil {
		return nil
	}
	fmt.Fprintf(b, "  # Security Feed SHA-256 %s\n", f.SHA256)
	var sets []feedSet
	for _, family := range []struct {
		match, typ string
		v4         bool
	}{
		{"ip", "ipv4_addr", true}, {"ip6", "ipv6_addr", false},
	} {
		values := feedFamily(f.Values, family.v4)
		if len(values) == 0 {
			continue
		}
		except := feedFamily(f.Exceptions, family.v4)
		fmt.Fprintf(b, "  set feed_%s {\n    type %s\n    flags interval\n    auto-merge\n    elements = { %s }\n  }\n",
			family.match, family.typ, strings.Join(values, ", "))
		if len(except) > 0 {
			fmt.Fprintf(b, "  set feed_allow_%s {\n    type %s\n    flags interval\n    auto-merge\n    elements = { %s }\n  }\n",
				family.match, family.typ, strings.Join(except, ", "))
		}
		sets = append(sets, feedSet{family.match, len(except) > 0})
	}
	return sets
}

func emitFeedRules(b *strings.Builder, sets []feedSet, revision *int64) {
	for _, s := range sets {
		for _, dir := range []string{"saddr", "daddr"} {
			match := fmt.Sprintf("%s %s @feed_%s", s.match, dir, s.match)
			if s.exceptions {
				match += fmt.Sprintf(" %s %s != @feed_allow_%s", s.match, dir, s.match)
			}
			if revision != nil {
				fmt.Fprintln(b, "   ", logRule(match, *revision, "forward", "drop", "@feed-"+s.match+"-"+dir))
			}
			fmt.Fprintf(b, "    %s counter drop comment \"gfw:feed:%s:%s\"\n", match, s.match, dir)
		}
	}
}
