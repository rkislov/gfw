//go:build linux

package wireguard

import (
	"github.com/vishvananda/netlink"
	"os"
	"testing"
)

func TestKernelStagedOwnershipAndForeignProtection(t *testing.T) {
	if os.Getenv("GFW_WG_KERNEL_TEST") != "1" {
		t.Skip("isolated privileged network namespace required")
	}
	c, v := testConfig(t)
	tun := c.Tunnels[0]
	tun.Name = "wgstage"
	c.Tunnels[0] = tun
	l := &Linux{Vault: v, LAN: "lan0"}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = tun.Name
	attrs.Group = ownerGroup(tun)
	link := &netlink.Wireguard{LinkAttrs: attrs}
	if e := netlink.LinkAdd(link); e != nil {
		t.Fatal(e)
	}
	defer netlink.LinkDel(link)
	if e := l.Activate(Empty(), c); e != nil {
		t.Fatal("unaliased but atomically tagged interface not recovered", e)
	}
	if _, e := netlink.LinkByName(tun.Name); e == nil {
		t.Fatal("partial interface remained")
	}
	attrs.Group = 0
	foreign := &netlink.Wireguard{LinkAttrs: attrs}
	if e := netlink.LinkAdd(foreign); e != nil {
		t.Fatal(e)
	}
	defer netlink.LinkDel(foreign)
	if e := l.Activate(Empty(), c); e == nil {
		t.Fatal("foreign interface adopted")
	}
	if _, e := netlink.LinkByName(tun.Name); e != nil {
		t.Fatal("foreign interface lost", e)
	}
}
