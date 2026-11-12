//go:build linux

package agent

import (
	"github.com/vishvananda/netlink"
	"net"
)

func routedFlowPorts() (map[string]bool, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	lowers := make(map[int]bool)
	for _, l := range links {
		a := l.Attrs()
		if l.Type() != "veth" && a.NetNsID < 0 && a.ParentIndex > 0 {
			lowers[a.ParentIndex] = true
		}
	}
	out := make(map[string]bool)
	for _, l := range links {
		a := l.Attrs()
		if (l.Type() == "device" || l.Type() == "veth") && a.MasterIndex == 0 && !lowers[a.Index] &&
			a.Flags&net.FlagUp != 0 && a.Flags&net.FlagLoopback == 0 && len(a.HardwareAddr) == 6 {
			out[a.Name] = true
		}
	}
	return out, nil
}
