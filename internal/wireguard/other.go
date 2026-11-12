//go:build !linux

package wireguard

import "errors"

type Linux struct {
	Vault *Vault
	LAN   string
}

func (l *Linux) GenerateKey(k string) (KeyInfo, error)        { return l.Vault.Generate(k) }
func (l *Linux) Export(c Config, t, p string) (string, error) { return l.Vault.ClientProfile(c, t, p) }
func (l *Linux) Prepare(c, old Config) (Plan, error) {
	return Preview(c), errors.New("WireGuard application requires Linux")
}
func (l *Linux) Activate(c, old Config) error {
	return errors.New("WireGuard application requires Linux")
}
func (l *Linux) Verify(c Config) error                   { return errors.New("WireGuard application requires Linux") }
func (l *Linux) Status(c Config) ([]TunnelStatus, error) { return []TunnelStatus{}, nil }
