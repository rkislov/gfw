//go:build !linux

package ipsec

import (
	"errors"
	"github.com/rkislov/gfw/internal/vpncred"
)

func NewLinux(*vpncred.Vault, string, string, string, string) (Backend, error) {
	return nil, errors.New("IPsec требует Linux")
}
