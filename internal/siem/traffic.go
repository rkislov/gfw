package siem

import (
	"strconv"
	"time"

	"github.com/rkislov/gfw/internal/traffic"
)

func TrafficEvent(host, version string, e traffic.Event) string {
	fields := []Field{
		{"externalId", e.EventID},
		{"deviceExternalId", e.Device},
	}
	add := func(key, value string) {
		if value != "" {
			fields = append(fields, Field{key, value})
		}
	}
	add("src", e.Source)
	add("dst", e.Destination)
	if e.SourcePort != 0 {
		add("spt", number(e.SourcePort))
	}
	if e.DestinationPort != 0 {
		add("dpt", number(e.DestinationPort))
	}
	add("proto", protocol(e.Protocol))
	if e.FlowID != "" {
		add("cs1Label", "Conntrack flow ID")
		add("cs1", e.FlowID)
	}
	if e.In != 0 {
		add("deviceInboundInterface", number(e.In))
	}
	if e.Out != 0 {
		add("deviceOutboundInterface", number(e.Out))
	}
	if e.NAT {
		if e.ReplyDestination != e.Source {
			add("sourceTranslatedAddress", e.ReplyDestination)
		}
		if e.ReplySource != e.Destination {
			add("destinationTranslatedAddress", e.ReplySource)
		}
		if e.ReplyDestinationPort != 0 && e.ReplyDestinationPort != e.SourcePort {
			add("sourceTranslatedPort", number(e.ReplyDestinationPort))
		}
		if e.ReplySourcePort != 0 && e.ReplySourcePort != e.DestinationPort {
			add("destinationTranslatedPort", number(e.ReplySourcePort))
		}
	}
	if e.Bytes != nil {
		add("out", number(*e.Bytes))
	}
	if e.ReplyBytes != nil {
		add("in", number(*e.ReplyBytes))
	}
	if e.Packets != nil {
		add("cn2Label", "Original packets")
		add("cn2", number(*e.Packets))
	}
	if e.ReplyPackets != nil {
		add("cn3Label", "Reply packets")
		add("cn3", number(*e.ReplyPackets))
	}
	at := time.UnixMilli(e.At).UTC().Format(time.RFC3339Nano)
	if e.Kind != "rule" {
		add("act", e.Kind)
		return Event(host, at, version, "gfw.conntrack."+e.Kind, "Conntrack "+e.Kind, 2, fields...)
	}
	add("act", e.Action)
	add("cs2Label", "Firewall rule ID")
	add("cs2", e.Rule)
	add("cs3Label", "Firewall direction")
	add("cs3", e.Direction)
	add("cn1Label", "Firewall revision")
	add("cn1", strconv.FormatInt(e.Revision, 10))
	severity := 3
	if e.Action == "drop" || e.Action == "reject" {
		severity = 5
	}
	return Event(host, at, version, "gfw.nflog."+e.Action, "Firewall rule "+e.Action, severity, fields...)
}

func number[T ~uint16 | ~uint32 | ~uint64](value T) string {
	return strconv.FormatUint(uint64(value), 10)
}

func protocol(n uint8) string {
	switch n {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		return strconv.Itoa(int(n))
	}
}
