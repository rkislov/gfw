//go:build !linux

package xdpguard

func New() Backend { return nil }
