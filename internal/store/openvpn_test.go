package store

import (
	"encoding/json"
	"github.com/rkislov/gfw/internal/openvpn"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVPNMigrationFromSchemaFourPreservesModules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx := t.Context()
	policy, e := s.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	policy.Config.Stateful = !policy.Config.Stateful
	policy, e = s.Save(ctx, policy.Revision, policy.Config)
	if e != nil {
		t.Fatal(e)
	}
	dns, e := s.ReadServices(ctx)
	if e != nil {
		t.Fatal(e)
	}
	wg, e := s.ReadWireGuard(ctx)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := json.Marshal([]any{policy, dns, wg})
	if _, e = s.db.Exec("DROP TABLE openvpn_config; UPDATE schema_version SET version=4"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	policy, e = s.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	dns, e = s.ReadServices(ctx)
	if e != nil {
		t.Fatal(e)
	}
	wg, e = s.ReadWireGuard(ctx)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal([]any{policy, dns, wg})
	if string(before) != string(after) {
		t.Fatal("migration changed existing module configuration")
	}
	ovpn, e := s.ReadOpenVPN(ctx)
	if e != nil || ovpn.Revision != 1 || len(ovpn.Config.Profiles) != 0 {
		t.Fatal("OpenVPN profile store not initialized", e)
	}
	var version int
	if e = s.db.QueryRow("SELECT version FROM schema_version").Scan(&version); e != nil || version != 10 {
		t.Fatal("wrong schema", version, e)
	}
}
func TestOpenVPNRuntimeAndExportsHaveIndependentStorage(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "gfw.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := openvpn.Profile{ID: strings.Repeat("a", 32), Name: "Export", ServerCertificateID: strings.Repeat("b", 32), ClientCertificateID: strings.Repeat("c", 32), Remote: "vpn.example.org", Port: 1194, Protocol: "udp"}
	if _, e = s.SaveOpenVPN(t.Context(), 1, openvpn.Config{Profiles: []openvpn.Profile{p}}); e != nil {
		t.Fatal(e)
	}
	i := openvpn.Instance{ID: strings.Repeat("d", 32), Name: "Server", Interface: "ovpn0", Mode: "server", Enabled: true, CertificateID: p.ServerCertificateID, Address: "10.80.0.1/24", BindAddress: "192.0.2.1", Port: 1194, Protocol: "udp"}
	if _, e = s.SaveOpenVPNRuntime(t.Context(), 1, openvpn.RuntimeConfig{Instances: []openvpn.Instance{i}}); e != nil {
		t.Fatal(e)
	}
	profiles, e := s.ReadOpenVPN(t.Context())
	if e != nil || profiles.Revision != 2 || len(profiles.Config.Profiles) != 1 || profiles.Config.Profiles[0].ID != p.ID {
		t.Fatal("runtime overwrote export profiles", e)
	}
	runtime, e := s.ReadOpenVPNRuntime(t.Context())
	if e != nil || runtime.Revision != 2 || len(runtime.Config.Instances) != 1 || runtime.Config.Instances[0].ID != i.ID {
		t.Fatal("profiles overwrote runtime", e)
	}
	if _, e = s.SaveOpenVPN(t.Context(), 2, openvpn.Config{}); e != nil {
		t.Fatal(e)
	}
	runtime, e = s.ReadOpenVPNRuntime(t.Context())
	if e != nil || len(runtime.Config.Instances) != 1 {
		t.Fatal("deleting profiles changed running config", e)
	}
}
