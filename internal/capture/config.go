package capture

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const FullSnaplen = 262144

type Config struct {
	Interface        string `json:"interface"`
	Backend          string `json:"backend"`
	Direction        string `json:"direction"`
	Family           string `json:"family"`
	Protocol         string `json:"protocol"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	SourcePorts      string `json:"source_ports"`
	DestinationPorts string `json:"destination_ports"`
	VLAN             *int   `json:"vlan"`
	Expert           string `json:"expert"`
	Snaplen          int    `json:"snaplen"`
	Seconds          int    `json:"seconds"`
	MaxPackets       int    `json:"max_packets"`
	MaxMiB           int    `json:"max_mib"`
	RotateFiles      int    `json:"rotate_files,omitempty"`
	RetentionHours   int    `json:"retention_hours"`
}

var ifaceName = regexp.MustCompile(`^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,14}$`)
var digits = regexp.MustCompile(`^[0-9]+$`)

func (c Config) Filter() (string, error) {
	if !ifaceName.MatchString(c.Interface) || c.Interface == "any" {
		return "", errors.New("выберите сетевой интерфейс")
	}
	if c.Direction != "in" && c.Direction != "out" && c.Direction != "inout" {
		return "", errors.New("выберите направление захвата")
	}
	switch c.Backend {
	case "auto", "packet":
	case "xdp", "xdp-generic":
		if c.Direction != "in" {
			return "", errors.New("XDP поддерживает только входящий трафик")
		}
	default:
		return "", errors.New("неизвестный способ захвата")
	}
	if c.Seconds < 1 || c.Seconds > 3600 || c.MaxPackets < 0 || c.MaxPackets > 10000000 ||
		c.MaxMiB < 1 || c.MaxMiB > 256 || c.RetentionHours < 1 || c.RetentionHours > 168 ||
		c.Snaplen != 0 && (c.Snaplen < 64 || c.Snaplen > FullSnaplen) {
		return "", errors.New("проверьте ограничения длительности, размера, пакетов, snaplen и срока хранения")
	}
	if c.RotateFiles != 0 && (c.RotateFiles < 2 || c.RotateFiles > 256) {
		return "", errors.New("для ротации укажите от 2 до 256 файлов")
	}
	if len(c.Expert) > 1024 || strings.ContainsAny(c.Expert, "\x00\r\n") {
		return "", errors.New("экспертный фильтр должен быть одной строкой до 1024 байт")
	}
	if expert := strings.TrimSpace(c.Expert); expert != "" {
		if c.Family != "" || c.Protocol != "" || c.Source != "" || c.Destination != "" ||
			c.SourcePorts != "" || c.DestinationPorts != "" || c.VLAN != nil {
			return "", errors.New("очистите обычные фильтры перед вводом экспертного выражения")
		}
		// Parentheses also keep a leading hyphen from becoming a command option.
		return "(" + expert + ")", nil
	}
	var conditions []string
	if c.VLAN != nil {
		if *c.VLAN < 0 || *c.VLAN > 4094 {
			return "", errors.New("VLAN ID должен быть от 0 до 4094")
		}
		conditions = append(conditions, fmt.Sprintf("vlan %d", *c.VLAN))
	}
	switch c.Family {
	case "":
	case "ip", "ip6", "arp":
		conditions = append(conditions, c.Family)
	default:
		return "", errors.New("неизвестный тип сетевого пакета")
	}
	switch c.Protocol {
	case "":
	case "tcp", "udp", "icmp", "icmp6", "esp":
		if c.Family == "arp" || c.Family == "ip" && c.Protocol == "icmp6" || c.Family == "ip6" && c.Protocol == "icmp" {
			return "", errors.New("тип пакета и протокол несовместимы")
		}
		conditions = append(conditions, c.Protocol)
	default:
		return "", errors.New("неизвестный протокол")
	}
	for _, item := range []struct{ side, address, ports string }{{"src", c.Source, c.SourcePorts}, {"dst", c.Destination, c.DestinationPorts}} {
		if value := strings.TrimSpace(item.address); value != "" {
			ip, ipErr := netip.ParseAddr(value)
			prefix, prefixErr := netip.ParsePrefix(value)
			switch {
			case ipErr == nil && ip.Zone() == "":
				conditions = append(conditions, item.side+" host "+ip.String())
			case prefixErr == nil:
				conditions = append(conditions, item.side+" net "+prefix.Masked().String())
			default:
				return "", errors.New("укажите корректный IP или CIDR")
			}
		}
		if value := strings.TrimSpace(item.ports); value != "" {
			if c.Protocol != "tcp" && c.Protocol != "udp" {
				return "", errors.New("для фильтра по портам выберите TCP или UDP")
			}
			ports, err := portFilter(item.side, value)
			if err != nil {
				return "", err
			}
			conditions = append(conditions, ports)
		}
	}
	return strings.Join(conditions, " and "), nil
}

func portFilter(side, value string) (string, error) {
	values := strings.Split(value, ",")
	if len(values) > 16 {
		return "", errors.New("допускается до 16 портов или диапазонов")
	}
	var parts []string
	for _, value := range values {
		a, b, pair := strings.Cut(strings.TrimSpace(value), "-")
		first, err := strconv.Atoi(a)
		if err != nil || !digits.MatchString(a) || first < 1 || first > 65535 {
			return "", errors.New("некорректный порт")
		}
		if !pair {
			parts = append(parts, fmt.Sprintf("%s port %d", side, first))
			continue
		}
		last, err := strconv.Atoi(b)
		if err != nil || !digits.MatchString(b) || last < first || last > 65535 {
			return "", errors.New("некорректный диапазон портов")
		}
		parts = append(parts, fmt.Sprintf("%s portrange %d-%d", side, first, last))
	}
	return "(" + strings.Join(parts, " or ") + ")", nil
}

func (c Config) effectiveSnaplen() int {
	if c.Snaplen == 0 {
		return FullSnaplen
	}
	return c.Snaplen
}
