package agent

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rkislov/gfw/internal/ids"
)

type testSensor struct {
	config ids.Config
}

func (s *testSensor) Prepare(c ids.Config) (ids.Plan, error) {
	return ids.Plan{Checked: true}, ids.Validate(c)
}
func (s *testSensor) Activate(c ids.Config) error {
	s.config = c
	return nil
}
func (s *testSensor) Verify(c ids.Config) error {
	if !reflect.DeepEqual(s.config, c) {
		return ErrConflict
	}
	return nil
}
func (s *testSensor) Status() ids.Status {
	return ids.Status{Running: s.config.Enabled}
}
func (s *testSensor) Alerts(int, int64) ([]ids.Alert, error) { return nil, nil }
func (s *testSensor) Logs() []string                         { return nil }
func (s *testSensor) Close() error                           { return nil }

func TestIPSDriftRollsBackWithoutReplacingFirewall(t *testing.T) {
	m, firewall, _ := testManager(t)
	ips := &fakeNFT{}
	m.SetIPSBackend(ips)
	sensor := &testSensor{}
	m.SetIDSBackend(sensor)
	c := ids.Config{Enabled: true, Mode: "ips", FailurePolicy: "closed",
		Interfaces: []string{"lan0", "wan0"}, HomeNet: []string{"192.0.2.0/24"},
		Rules: "drop udp any any -> any any (sid:1000001;)"}
	if _, err := m.IDSPlan(c); err == nil {
		t.Fatal("IPS enabled before baseline firewall was confirmed")
	}
	first, err := m.Apply(req("base-firewall"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(first.ID); err != nil {
		t.Fatal(err)
	}
	base := firewall.live
	replacements := firewall.replaces
	change := IDSRequest{ID: "ips-change-1", Revision: 1, TimeoutSeconds: 60, Config: c}
	if _, err := m.IDSApply(change); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ips.live.Rules, "hook forward priority 10") || strings.Contains(ips.live.Rules, "bypass") {
		t.Fatal(ips.live.Rules)
	}
	if _, err := m.Confirm(change.ID); err != nil {
		t.Fatal(err)
	}
	closed := ips.live
	change.ID, change.Revision, change.Config.FailurePolicy = "ips-change-2", 2, "open"
	if _, err := m.IDSApply(change); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ips.live.Rules, "bypass") {
		t.Fatal(ips.live.Rules)
	}
	ips.live = Snapshot{}
	if _, err := m.Confirm(change.ID); err == nil {
		t.Fatal("confirmed IPS after external removal of its table")
	}
	if ips.live != closed || sensor.config.FailurePolicy != "closed" || firewall.live != base ||
		firewall.replaces != replacements || m.State().Pending != nil {
		t.Fatal("drift rollback did not restore the previous IPS configuration independently")
	}
}
