package agent

import (
	"errors"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/services"
	"reflect"
	"testing"
	"time"
)

type fakeOVPN struct {
	current           openvpn.RuntimeConfig
	fail, failRestore bool
}

func (f *fakeOVPN) Prepare(c, old openvpn.RuntimeConfig) (openvpn.Plan, error) {
	return openvpn.PreviewRuntime(c), openvpn.ValidateRuntime(c)
}
func (f *fakeOVPN) Activate(c, old openvpn.RuntimeConfig) error {
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
func (f *fakeOVPN) Verify(c openvpn.RuntimeConfig) error {
	if !reflect.DeepEqual(f.current, c) {
		return errors.New("WG drift")
	}
	return nil
}
func (f *fakeOVPN) Status(c openvpn.RuntimeConfig) ([]openvpn.Status, error) {
	return []openvpn.Status{}, nil
}
func TestOpenVPNTransactionRecoverAndVersion(t *testing.T) {
	m, nft, dir := testManager(t)
	wg := &fakeOVPN{current: openvpn.RuntimeEmpty()}
	m.SetOpenVPNBackend(wg)
	r, e := m.OpenVPNApply(OpenVPNRequest{ID: "wg-confirm-test", Revision: 2, TimeoutSeconds: 30, Config: openvpn.RuntimeEmpty()})
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
	if m.j.Version != 6 {
		t.Fatal("service downgraded journal")
	}
	m.Close()
	next, e := NewManager(dir, nft, m.safety)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.SetServicesBackend(&fakeServices{})
	next.SetOpenVPNBackend(&fakeOVPN{current: openvpn.RuntimeEmpty()})
	if e = next.Recover(); e != nil || next.OpenVPNState().ConfirmedRevision != 2 {
		t.Fatal("WG recovery", e)
	}
}
func TestOpenVPNTimeoutPartialFailureAndRetry(t *testing.T) {
	m, _, _ := testManager(t)
	wg := &fakeOVPN{current: openvpn.RuntimeEmpty()}
	m.SetOpenVPNBackend(wg)
	now := time.Now()
	m.now = func() time.Time { return now }
	r := OpenVPNRequest{ID: "wg-timeout-test", Revision: 1, TimeoutSeconds: 30, Config: openvpn.RuntimeEmpty()}
	if _, e := m.OpenVPNApply(r); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	if e := m.Tick(); e != nil || m.j.Pending != nil {
		t.Fatal("timeout failed", e)
	}
	wg.fail = true
	r.ID = "wg-partial-test"
	if _, e := m.OpenVPNApply(r); e == nil || m.j.Pending != nil {
		t.Fatal("partial activation not restored", e)
	}
	r.ID = "wg-rollback-test"
	if _, e := m.OpenVPNApply(r); e != nil {
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

func (f *fakeOVPN) Stage([]openvpn.Material, openvpn.RuntimeConfig) error    { return nil }
func (f *fakeOVPN) Refresh([]openvpn.CRLUpdate, openvpn.RuntimeConfig) error { return nil }
func (f *fakeOVPN) CAs(openvpn.RuntimeConfig) []string                       { return nil }
func (f *fakeOVPN) Logs(string) ([]string, error)                            { return nil, nil }
func (f *fakeOVPN) Maintain(openvpn.RuntimeConfig) error                     { return nil }
