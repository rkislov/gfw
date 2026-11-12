package agent

import (
	"errors"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/services"
	"testing"
	"time"
)

type fakeServices struct {
	config            services.Config
	fail, failRestore bool
	activations       int
}

func (f *fakeServices) Prepare(c services.Config) (services.Plan, error) {
	return services.Preview(c), services.Validate(c)
}
func (f *fakeServices) Activate(c services.Config) error {
	f.config = c
	f.activations++
	if f.fail {
		f.fail = false
		return errors.New("partial service activation")
	}
	if f.failRestore {
		return errors.New("restore failed")
	}
	return nil
}
func (f *fakeServices) Verify(c services.Config) error {
	if !services.Equal(c, f.config) {
		return errors.New("runtime mismatch")
	}
	return nil
}
func (f *fakeServices) Close() error { return nil }
func (f *fakeServices) Status() services.Status {
	return services.Status{DNSRunning: f.config.DNS.Enabled}
}
func serviceRequest(id string) ServicesRequest {
	c := services.Default()
	c.DNS.Enabled = true
	c.DNS.Address = "192.0.2.1"
	c.DNS.Interface = "lan0"
	c.DNS.AllowedClients = []string{"192.0.2.0/24"}
	return ServicesRequest{ID: id, Revision: 2, TimeoutSeconds: 30, Config: c}
}
func TestServicesConfirmRecoverAndSharedTransaction(t *testing.T) {
	m, nft, dir := testManager(t)
	b := &fakeServices{}
	m.SetServicesBackend(b)
	r, e := m.ServicesApply(serviceRequest("services-confirm"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(req("blocked-firewall")); !errors.Is(e, ErrConflict) {
		t.Fatal("overlap allowed", e)
	}
	if _, e = m.ServicesApply(serviceRequest(r.ID)); e != nil || b.activations != 1 {
		t.Fatal("idempotency failed", e)
	}
	if _, e = m.Confirm(r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Apply(req("services-then-firewall")); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Confirm("services-then-firewall"); e != nil {
		t.Fatal(e)
	}
	if m.j.Version != 4 {
		t.Fatal("firewall downgraded service journal")
	}
	m.Close()
	next, e := NewManager(dir, nft, m.safety)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.validateLAN = func() error { return nil }
	runtime := &fakeServices{}
	next.SetServicesBackend(runtime)
	if e = next.Recover(); e != nil {
		t.Fatal(e)
	}
	if !runtime.config.DNS.Enabled || next.j.Version != 4 || next.ServicesState().ConfirmedRevision != 2 {
		t.Fatal("confirmed services not restored")
	}
}
func TestServicesTimeoutFailureAndRecoveryRetry(t *testing.T) {
	m, _, _ := testManager(t)
	b := &fakeServices{}
	m.SetServicesBackend(b)
	now := time.Now()
	m.now = func() time.Time { return now }
	r, e := m.ServicesApply(serviceRequest("services-timeout"))
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	if e = m.Tick(); e != nil || b.config.DNS.Enabled {
		t.Fatal("timeout did not restore", e)
	}
	if _, e = m.Confirm(r.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("late confirm accepted")
	}
	b.fail = true
	if _, e = m.ServicesApply(serviceRequest("services-partial")); e == nil || m.j.Pending != nil || b.config.DNS.Enabled {
		t.Fatal("partial failure not rolled back", e)
	}
	if _, e = m.ServicesApply(serviceRequest("services-retry")); e != nil {
		t.Fatal(e)
	}
	b.failRestore = true
	if _, e = m.Rollback("services-retry"); e == nil || m.j.Pending.Record.Status != "rollback_failed" {
		t.Fatal("failed rollback lost intent", e)
	}
	b.failRestore = false
	if e = m.Tick(); e != nil || m.j.Pending != nil {
		t.Fatal("rollback retry failed", e)
	}
}
func TestServiceInterfaceAndAddressDependencies(t *testing.T) {
	m, _, _ := testManager(t)
	c := serviceRequest("dependencies").Config
	m.j.ServicesConfirmed = &c
	network := netconfig.Config{Interfaces: []netconfig.Link{{Name: "lan0", Type: "physical", Up: true, Addresses: []string{"192.0.2.1/24"}}}}
	m.j.NetworkConfirmed = &network
	if e := m.checkServiceDependencies(netconfig.Empty()); e == nil {
		t.Fatal("used interface removed")
	}
	network2 := network
	network2.Interfaces = append([]netconfig.Link{}, network.Interfaces...)
	network2.Interfaces[0].Addresses = []string{"192.0.2.2/24"}
	if e := m.checkServiceDependencies(network2); e == nil {
		t.Fatal("used address removed")
	}
	if e := m.checkServiceDependencies(network); e != nil {
		t.Fatal(e)
	}
}

func TestDNSCannotTakeManagementPort(t *testing.T) {
	m, _, _ := testManager(t)
	m.SetServicesBackend(&fakeServices{})
	r := serviceRequest("management-port")
	r.Config.DNS.Port = 8443
	if _, e := m.ServicesPlan(r.Config); e == nil {
		t.Fatal("management port offered to DNS")
	}
	if _, e := m.ServicesApply(r); e == nil || m.j.Pending != nil {
		t.Fatal("management port change started", e)
	}
}

func TestNetworkServiceRebindFailureRestoresBoth(t *testing.T) {
	m, _, _ := testManager(t)
	network := &fakeNetwork{current: netconfig.Empty()}
	m.SetNetworkBackend(network)
	c := services.Default()
	m.j.ServicesConfirmed = &c
	backend := &fakeServices{fail: true}
	m.SetServicesBackend(backend)
	if _, e := m.NetworkApply(networkReq("service-rebind-failure")); e == nil || m.j.Pending != nil || len(network.current.Interfaces) != 0 || backend.activations != 2 {
		t.Fatal("network/service rollback incomplete", e, backend.activations)
	}
}
