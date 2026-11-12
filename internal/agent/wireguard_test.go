package agent

import (
	"errors"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/wireguard"
	"reflect"
	"testing"
	"time"
)

type fakeWG struct {
	current           wireguard.Config
	fail, failRestore bool
}

func (f *fakeWG) Prepare(c, old wireguard.Config) (wireguard.Plan, error) {
	return wireguard.Preview(c), wireguard.Validate(c)
}
func (f *fakeWG) Activate(c, old wireguard.Config) error {
	f.current = c
	if f.fail {
		f.fail = false
		return errors.New("partial WG failure")
	}
	if f.failRestore {
		return errors.New("restore failed")
	}
	return nil
}
func (f *fakeWG) Verify(c wireguard.Config) error {
	if !reflect.DeepEqual(f.current, c) {
		return errors.New("WG drift")
	}
	return nil
}
func (f *fakeWG) Status(c wireguard.Config) ([]wireguard.TunnelStatus, error) {
	return []wireguard.TunnelStatus{}, nil
}
func (f *fakeWG) GenerateKey(string) (wireguard.KeyInfo, error)           { return wireguard.KeyInfo{}, nil }
func (f *fakeWG) Export(wireguard.Config, string, string) (string, error) { return "", nil }
func TestWireGuardTransactionRecoverAndVersion(t *testing.T) {
	m, nft, dir := testManager(t)
	wg := &fakeWG{current: wireguard.Empty()}
	m.SetWireGuardBackend(wg)
	r, e := m.WireGuardApply(WireGuardRequest{ID: "wg-confirm-test", Revision: 2, TimeoutSeconds: 30, Config: wireguard.Empty()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(req("blocked-by-wg")); !errors.Is(e, ErrConflict) {
		t.Fatal("overlap", e)
	}
	if _, e = m.Confirm(r.ID); e != nil {
		t.Fatal(e)
	}
	m.SetServicesBackend(&fakeServices{})
	if _, e = m.ServicesApply(ServicesRequest{ID: "services-after-wg", Revision: 2, TimeoutSeconds: 30, Config: services.Default()}); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Confirm("services-after-wg"); e != nil {
		t.Fatal(e)
	}
	if m.j.Version != 5 {
		t.Fatal("service downgraded journal")
	}
	m.Close()
	next, e := NewManager(dir, nft, m.safety)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.SetServicesBackend(&fakeServices{})
	next.SetWireGuardBackend(&fakeWG{current: wireguard.Empty()})
	if e = next.Recover(); e != nil || next.WireGuardState().ConfirmedRevision != 2 {
		t.Fatal("WG recovery", e)
	}
}
func TestWireGuardTimeoutPartialFailureAndRetry(t *testing.T) {
	m, _, _ := testManager(t)
	wg := &fakeWG{current: wireguard.Empty()}
	m.SetWireGuardBackend(wg)
	now := time.Now()
	m.now = func() time.Time { return now }
	r := WireGuardRequest{ID: "wg-timeout-test", Revision: 1, TimeoutSeconds: 30, Config: wireguard.Empty()}
	if _, e := m.WireGuardApply(r); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	if e := m.Tick(); e != nil || m.j.Pending != nil {
		t.Fatal("timeout failed", e)
	}
	wg.fail = true
	r.ID = "wg-partial-test"
	if _, e := m.WireGuardApply(r); e == nil || m.j.Pending != nil {
		t.Fatal("partial activation not restored", e)
	}
	r.ID = "wg-rollback-test"
	if _, e := m.WireGuardApply(r); e != nil {
		t.Fatal(e)
	}
	wg.failRestore = true
	if _, e := m.Rollback(r.ID); e == nil || m.j.Pending.Record.Status != "rollback_failed" {
		t.Fatal("failed rollback lost", e)
	}
	wg.failRestore = false
	if e := m.Tick(); e != nil || m.j.Pending != nil {
		t.Fatal("retry failed", e)
	}
}
func TestWireGuardModuleDependencies(t *testing.T) {
	m, _, _ := testManager(t)
	c := wireguard.Config{Tunnels: []wireguard.Tunnel{{Name: "wg0", Enabled: true, Addresses: []string{"10.50.0.1/24"}}}}
	m.j.WireGuardConfirmed = &c
	fw := policy.Default()
	fw.Zones = []policy.Zone{{ID: "vpn", Name: "VPN", Kind: "vpn", Interfaces: []string{"wg0"}}}
	m.j.FirewallConfig = &fw
	if e := m.wireGuardSafety(wireguard.Empty()); e == nil {
		t.Fatal("used zone tunnel deleted")
	}
	m.j.FirewallConfig = nil
	s := services.Default()
	s.DNS.Enabled = true
	s.DNS.Interface = "wg0"
	s.DNS.Address = "10.50.0.1"
	m.j.ServicesConfirmed = &s
	if e := m.wireGuardSafety(wireguard.Empty()); e == nil {
		t.Fatal("DNS dependency ignored")
	}
	if e := m.checkZoneDependencies(netconfig.Config{Interfaces: []netconfig.Link{{Name: "wg0", Type: "physical"}}}); e == nil {
		t.Fatal("network can take WG interface")
	}
}
