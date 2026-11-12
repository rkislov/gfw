package wireguard

type Backend interface {
	Prepare(Config, Config) (Plan, error)
	Activate(Config, Config) error
	Verify(Config) error
	Status(Config) ([]TunnelStatus, error)
	GenerateKey(string) (KeyInfo, error)
	Export(Config, string, string) (string, error)
}
