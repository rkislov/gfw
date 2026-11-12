//go:build !linux

package server

import "errors"

func ListenInterface(addr, iface string) (*Listener, error) {
	return nil, errors.New("DHCP interface binding requires Linux")
}
