//go:build !linux

package openvpn

import "errors"

type Linux struct{}

func NewLinux(*Vault, string, string, string) (*Linux, error) {
	return nil, errors.New("OpenVPN agent requires Linux")
}
func (*Linux) Stage([]Material, RuntimeConfig) error    { return errors.New("requires Linux") }
func (*Linux) Refresh([]CRLUpdate, RuntimeConfig) error { return errors.New("requires Linux") }
func (*Linux) CAs(RuntimeConfig) []string               { return []string{} }
func (*Linux) Prepare(c, old RuntimeConfig) (Plan, error) {
	return PreviewRuntime(c), errors.New("requires Linux")
}
func (*Linux) Activate(RuntimeConfig, RuntimeConfig) error { return errors.New("requires Linux") }
func (*Linux) Verify(RuntimeConfig) error                  { return errors.New("requires Linux") }
func (*Linux) Status(RuntimeConfig) ([]Status, error)      { return []Status{}, nil }
func (*Linux) Logs(string) ([]string, error)               { return []string{}, nil }
func (*Linux) Maintain(RuntimeConfig) error                { return nil }
func (*Linux) Close() error                                { return nil }
