// GFW integration: bind a DHCP socket exclusively to one selected interface.
package server

import (
	"context"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func ListenInterface(addr, iface string) (*Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var optionErr error
		err := c.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if optionErr == nil {
				optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
			if optionErr == nil {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
	conn, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, err
	}
	udp := conn.(*net.UDPConn)
	_ = udp.SetReadBuffer(4 << 20)
	pc := ipv4.NewPacketConn(udp)
	if err = pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		udp.Close()
		return nil, err
	}
	return &Listener{conn: udp, pc: pc, control: true}, nil
}
