package wireguard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) (Config, *Vault) {
	t.Helper()
	v, e := OpenVault(filepath.Join(t.TempDir(), "keys"))
	if e != nil {
		t.Fatal(e)
	}
	server, e := v.Generate("tunnel")
	if e != nil {
		t.Fatal(e)
	}
	client, e := v.Generate("client")
	if e != nil {
		t.Fatal(e)
	}
	psk, e := v.Generate("psk")
	if e != nil {
		t.Fatal(e)
	}
	return Config{Tunnels: []Tunnel{{ID: NewID(), Name: "wg0", Enabled: true, KeyRef: server.Ref, PublicKey: server.PublicKey, ListenPort: 51820, MTU: 1420, Addresses: []string{"10.50.0.1/24"}, InstallRoutes: true, ClientEndpoint: "vpn.example.org:51820", Peers: []Peer{{ID: NewID(), Name: "Client", Enabled: true, PublicKey: client.PublicKey, KeyRef: client.Ref, PSKRef: psk.Ref, AllowedIPs: []string{"10.50.0.2/32"}, Keepalive: 25, ClientAddresses: []string{"10.50.0.2/32"}, ClientRoutes: []string{"10.50.0.0/24"}}}}}}, v
}
func TestValidationRejectsUnsafeRoutingAndProfiles(t *testing.T) {
	c, _ := testConfig(t)
	if e := Validate(c); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Config){"host bits": func(c *Config) { c.Tunnels[0].Peers[0].AllowedIPs = []string{"10.50.0.2/24"} }, "LAN name": func(c *Config) { c.Tunnels[0].Name = "br-lan" }, "default route": func(c *Config) { c.Tunnels[0].Peers[0].AllowedIPs = []string{"0.0.0.0/0"} }, "endpoint loop": func(c *Config) { c.Tunnels[0].Peers[0].Endpoint = "10.50.0.2:51820" }, "peer overlap": func(c *Config) {
		p := c.Tunnels[0].Peers[0]
		p.ID = NewID()
		p.PublicKey = c.Tunnels[0].PublicKey
		c.Tunnels[0].Peers = append(c.Tunnels[0].Peers, p)
	}, "export injection": func(c *Config) { c.Tunnels[0].ClientEndpoint = "vpn.example.org:51820\nPostUp = bad" }, "client outside allowed": func(c *Config) { c.Tunnels[0].Peers[0].ClientAddresses = []string{"10.60.0.2/32"} }, "IPv6 MTU": func(c *Config) { c.Tunnels[0].Addresses = []string{"fd50::1/64"}; c.Tunnels[0].MTU = 1000 }}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var next Config
			json.Unmarshal(raw, &next)
			modify(&next)
			if Validate(next) == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}
func TestVaultAndExplicitClientExport(t *testing.T) {
	c, v := testConfig(t)
	if e := v.Validate(c); e != nil {
		t.Fatal(e)
	}
	tunnel := c.Tunnels[0]
	peer := tunnel.Peers[0]
	key, _ := v.Key(peer.KeyRef, "client")
	raw, e := os.ReadFile(filepath.Join(v.root, peer.KeyRef+".key"))
	if e != nil || bytes.Contains(raw, []byte(key.String())) || bytes.Contains(raw, key[:]) {
		t.Fatal("secret stored unencrypted", e)
	}
	body, _ := json.Marshal(c)
	if bytes.Contains(body, []byte(key.String())) {
		t.Fatal("draft leaked private key")
	}
	profile, e := v.ClientProfile(c, tunnel.ID, peer.ID)
	if e != nil || !strings.Contains(profile, "PrivateKey = "+key.String()) || !strings.Contains(profile, "PresharedKey = ") {
		t.Fatal("client export invalid", e)
	}
	raw[len(raw)-1] ^= 1
	os.WriteFile(filepath.Join(v.root, peer.KeyRef+".key"), raw, 0600)
	if _, e = v.Key(peer.KeyRef, "client"); e == nil {
		t.Fatal("tampered encrypted key accepted")
	}
	os.Remove(filepath.Join(v.root, "device.key"))
	if _, e = OpenVault(v.root); e == nil {
		t.Fatal("lost device key silently regenerated")
	}
}

func TestTunnelKeyCannotBeExportedAsClient(t *testing.T) {
	c, v := testConfig(t)
	other, e := v.Generate("tunnel")
	if e != nil {
		t.Fatal(e)
	}
	p := &c.Tunnels[0].Peers[0]
	p.KeyRef = other.Ref
	p.PublicKey = other.PublicKey
	if e = Validate(c); e != nil {
		t.Fatal("public model should not contain secret roles", e)
	}
	if _, e = v.ClientProfile(c, c.Tunnels[0].ID, p.ID); e == nil {
		t.Fatal("tunnel private key exported as client")
	}
}
