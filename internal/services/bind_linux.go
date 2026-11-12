package services

import (
	"golang.org/x/sys/unix"
	"syscall"
)

func bindInterface(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var e error
		err := c.Control(func(fd uintptr) { e = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name) })
		if err != nil {
			return err
		}
		return e
	}
}
