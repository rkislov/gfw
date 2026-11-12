package traffic

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// ExportFilter selects traffic events for SIEM. An empty source list disables
// that source. Common filters apply to the original and reply tuples.
type ExportFilter struct {
	Conntrack []string `json:"conntrack"`
	NFLOG     []string `json:"nflog"`
	IP        string   `json:"ip"`
	Port      uint16   `json:"port"`
	Protocol  *uint8   `json:"protocol"`
	Rule      string   `json:"rule"`
	Direction string   `json:"direction"`
}

var exportRuleID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

func (f ExportFilter) Enabled() bool { return len(f.Conntrack) > 0 || len(f.NFLOG) > 0 }

func (f ExportFilter) Compile() (func(Event) bool, error) {
	if !validSelection(f.Conntrack, []string{"new", "update", "destroy", "snapshot"}) ||
		!validSelection(f.NFLOG, []string{"accept", "drop", "reject"}) {
		return nil, errors.New("Неизвестный тип conntrack или действие NFLOG")
	}
	if f.Rule != "" && !exportRuleID.MatchString(f.Rule) {
		return nil, errors.New("Некорректный ID правила NFLOG")
	}
	if f.Direction != "" && !slices.Contains([]string{"input", "output", "forward"}, f.Direction) {
		return nil, errors.New("Неизвестное направление NFLOG")
	}
	var prefix netip.Prefix
	if value := strings.TrimSpace(f.IP); value != "" {
		var err error
		prefix, err = netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil || addr.Zone() != "" {
				return nil, errors.New("Укажите IP или CIDR")
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
	}
	return func(e Event) bool {
		if e.Kind == "rule" {
			if !slices.Contains(f.NFLOG, e.Action) || f.Rule != "" && e.Rule != f.Rule ||
				f.Direction != "" && e.Direction != f.Direction {
				return false
			}
		} else if !slices.Contains(f.Conntrack, e.Kind) {
			return false
		}
		if f.Protocol != nil && e.Protocol != *f.Protocol ||
			f.Port != 0 && f.Port != e.SourcePort && f.Port != e.DestinationPort &&
				f.Port != e.ReplySourcePort && f.Port != e.ReplyDestinationPort {
			return false
		}
		if !prefix.IsValid() {
			return true
		}
		for _, raw := range [4]string{e.Source, e.Destination, e.ReplySource, e.ReplyDestination} {
			addr, err := netip.ParseAddr(raw)
			if err == nil && (prefix.Contains(addr) || prefix.Contains(addr.Unmap())) {
				return true
			}
		}
		return false
	}, nil
}

func validSelection(values, allowed []string) bool {
	if len(values) > len(allowed) {
		return false
	}
	for i, value := range values {
		if !slices.Contains(allowed, value) || slices.Contains(values[:i], value) {
			return false
		}
	}
	return true
}
