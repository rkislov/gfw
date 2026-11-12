//go:build !linux

package services

import (
	"errors"
	"syscall"
)

func bindInterface(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error { return errors.New("DNS interface binding requires Linux") }
}
