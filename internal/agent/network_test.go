package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/policy"
)

type fakeNetwork struct {
	current                   netconfig.Config
	failActivate, failRestore bool
	restores                  int
}

func TestConfirmedZonePreventsDeletingManagedInterface(t *testing.T) {
	m, _, _ := testManager(t)
	c := networkReq("zone-dependency").Config
	m.SetNetworkBackend(&fakeNetwork{current: c})
	m.j.NetworkConfirmed = &c
	policyConfig := policy.Default()
	policyConfig.Zones = []policy.Zone{{ID: "office", Name: "Office", Kind: "lan", Interfaces: []string{"v100"}}}
	m.j.FirewallConfig = &policyConfig
	if _, err := m.NetworkPlan(netconfig.Empty()); err == nil {
		t.Fatal("removed interface referenced by confirmed zone")
	}
	r := networkReq("zone-removal")
	r.Config = netconfig.Empty()
	if _, err := m.NetworkApply(r); err == nil || m.j.Pending != nil {
		t.Fatal("unsafe removal started a transaction", err)
	}
	policyConfig.Zones = nil
	if _, err := m.NetworkPlan(netconfig.Empty()); err != nil {
		t.Fatal("interface cannot be removed after zone reference is removed", err)
	}
}

func (f *fakeNetwork) Prepare(c, old netconfig.Config) (netconfig.Snapshot, netconfig.Plan, error) {
	s := netconfig.Snapshot{}
	for _, l := range f.current.Interfaces {
		s.Links = append(s.Links, netconfig.RuntimeLink{Link: l})
	}
	for _, r := range f.current.Routes {
		s.Routes = append(s.Routes, netconfig.RuntimeRoute{Route: r})
	}
	return s, netconfig.Plan{CanApply: true}, nil
}
func (f *fakeNetwork) Activate(c, old netconfig.Config) error {
	f.current = c
	if f.failActivate {
		return errors.New("partial kernel/file failure")
	}
	return nil
}
func (f *fakeNetwork) Restore(s netconfig.Snapshot) error {
	f.restores++
	if f.failRestore {
		return errors.New("restore failed")
	}
	f.current = netconfig.Empty()
	for _, l := range s.Links {
		f.current.Interfaces = append(f.current.Interfaces, l.Link)
	}
	for _, r := range s.Routes {
		f.current.Routes = append(f.current.Routes, r.Route)
	}
	return nil
}
func (f *fakeNetwork) Verify(netconfig.Config) error { return nil }
func networkReq(id string) NetworkRequest {
	return NetworkRequest{ID: id, Revision: 4, TimeoutSeconds: 30, Config: netconfig.Config{Interfaces: []netconfig.Link{{Name: "v100", Type: "vlan", MTU: 1500, Up: true, Parent: "eth0", VLAN: 100}}, Routes: []netconfig.Route{}}}
}
func TestNetworkAndFirewallShareTransactionAndRollback(t *testing.T) {
	m, _, _ := testManager(t)
	n := &fakeNetwork{current: netconfig.Empty()}
	m.SetNetworkBackend(n)
	r, err := m.NetworkApply(networkReq("net-transaction"))
	if err != nil || r.Kind != "network" {
		t.Fatal(r, err)
	}
	if _, err = m.Apply(req("firewall-block")); !errors.Is(err, ErrConflict) {
		t.Fatal("firewall overlapped network")
	}
	if _, err = m.NetworkApply(networkReq(r.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(r.ID); err != nil {
		t.Fatal(err)
	}
	if m.NetworkState().ConfirmedRevision != 4 || m.State().ConfirmedRevision != 0 {
		t.Fatal("network confirmation changed firewall revision")
	}
	changed := networkReq("net-timeout")
	changed.Config = netconfig.Empty()
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err = m.NetworkApply(changed); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err = m.Tick(); err != nil || len(n.current.Interfaces) != 1 {
		t.Fatal("network timeout did not restore", err)
	}
}
func TestPartialNetworkFailureAndFailedRecoveryRetry(t *testing.T) {
	m, _, _ := testManager(t)
	n := &fakeNetwork{current: netconfig.Empty(), failActivate: true, failRestore: true}
	m.SetNetworkBackend(n)
	if _, err := m.NetworkApply(networkReq("net-failure")); err == nil {
		t.Fatal("partial failure hidden")
	}
	if m.NetworkState().Pending.Status != "rollback_failed" {
		t.Fatal("failed recovery not persisted")
	}
	n.failRestore = false
	if err := m.Tick(); err != nil || m.NetworkState().Pending != nil || len(n.current.Interfaces) != 0 {
		t.Fatal("network recovery retry failed", err)
	}
}
func TestNetworkCrashRecoveryAlsoRestoresConfirmedFirewall(t *testing.T) {
	m, b, dir := testManager(t)
	if _, err := m.Apply(req("firewall-confirm")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm("firewall-confirm"); err != nil {
		t.Fatal(err)
	}
	n := &fakeNetwork{current: netconfig.Empty()}
	m.SetNetworkBackend(n)
	if _, err := m.NetworkApply(networkReq("network-crash")); err != nil {
		t.Fatal(err)
	}
	m.Close()
	b.live = Snapshot{}
	next, err := NewManager(dir, b, m.safety)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.SetNetworkBackend(n)
	next.validateLAN = func() error { return nil }
	if err = next.Recover(); err != nil || !b.live.Exists || len(n.current.Interfaces) != 0 || next.State().Pending != nil {
		t.Fatal("recovery did not restore both subsystems", err)
	}
}
