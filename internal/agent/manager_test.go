package agent

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/policy"
)

type fakeNFT struct {
	live                   Snapshot
	failCheck, failReplace bool
	replaces               int
	ambiguous              bool
}

func (f *fakeNFT) Snapshot() (Snapshot, error) { return f.live, nil }
func (f *fakeNFT) Check(Snapshot) error {
	if f.failCheck {
		return errors.New("check rejected")
	}
	return nil
}
func (f *fakeNFT) Replace(s Snapshot) error {
	f.replaces++
	if f.ambiguous {
		f.live = s
		f.ambiguous = false
		return errors.New("uncertain timeout after commit")
	}
	if f.failReplace {
		return errors.New("replace failed")
	}
	f.live = s
	return nil
}
func testManager(t *testing.T) (*Manager, *fakeNFT, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	b := &fakeNFT{}
	m, err := NewManager(dir, b, policy.Safety{LANInterface: "lan0", ManagementPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	m.validateLAN = func() error { return nil }
	t.Cleanup(func() { m.Close() })
	return m, b, dir
}
func req(id string) ApplyRequest {
	return ApplyRequest{ID: id, Revision: 1, TimeoutSeconds: 30, Config: policy.Default()}
}
func TestApplyConfirmRestartAndIdempotency(t *testing.T) {
	m, b, dir := testManager(t)
	r, err := m.Apply(req("change-0001"))
	if err != nil || r.Status != "pending" {
		t.Fatal(r, err)
	}
	if !strings.Contains(b.live.Rules, "gfw:anti-lockout") {
		t.Fatal("missing management protection")
	}
	n := b.replaces
	if _, err = m.Apply(req(r.ID)); err != nil || b.replaces != n {
		t.Fatal("retry applied twice", err)
	}
	other := req(r.ID)
	other.TimeoutSeconds = 60
	if _, err = m.Apply(other); !errors.Is(err, ErrConflict) {
		t.Fatal("reused id accepted")
	}
	if _, err = m.Apply(req("change-0002")); !errors.Is(err, ErrConflict) {
		t.Fatal("overlapping transaction accepted")
	}
	if _, err = m.Confirm("wrong-id"); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong confirmation accepted")
	}
	if _, err = m.Confirm(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Confirm(r.ID); err != nil {
		t.Fatal("confirm not idempotent", err)
	}
	m.Close()
	b.live = Snapshot{}
	recovered, err := NewManager(dir, b, m.safety)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	recovered.validateLAN = func() error { return nil }
	if err = recovered.Recover(); err != nil || !b.live.Exists || recovered.State().ConfirmedRevision != 1 {
		t.Fatal("confirmed rules not restored", err)
	}
	if recovered.j.Version != 3 || recovered.j.FirewallConfig == nil || len(recovered.j.FirewallConfig.Zones) != 4 {
		t.Fatal("confirmed zone dependencies were not persisted")
	}
}
func TestTimeoutRollbackAndLateConfirmation(t *testing.T) {
	m, b, _ := testManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	r, err := m.Apply(req("change-timeout"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if _, err = m.Confirm(r.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("deadline boundary accepted")
	}
	if b.live.Exists || m.State().Pending != nil {
		t.Fatal("not rolled back")
	}
	r, err = m.Apply(req(r.ID))
	if err != nil || r.Status != "rolled_back" {
		t.Fatal("retry reapplied expired operation", r, err)
	}
}
func TestCrashBetweenKernelAndJournalRollsBackImmediately(t *testing.T) {
	m, b, dir := testManager(t)
	_, err := m.Apply(req("change-crash"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a durable pre-nft intent, without the post-nft fsync.
	m.j.Pending.Record.Status = "applying"
	if err = m.save(m.j); err != nil {
		t.Fatal(err)
	}
	m.Close()
	recovered, err := NewManager(dir, b, m.safety)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if err = recovered.Recover(); err != nil || b.live.Exists {
		t.Fatal("crash recovery did not restore absent original table", err)
	}
	if recovered.State().History[0].Status != "rolled_back" {
		t.Fatal("missing recovery outcome")
	}
}
func TestRollbackFailureRetriesAndBlocksApply(t *testing.T) {
	m, b, _ := testManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	_, err := m.Apply(req("change-failure"))
	if err != nil {
		t.Fatal(err)
	}
	b.failReplace = true
	now = now.Add(time.Minute)
	if m.Tick() == nil {
		t.Fatal("rollback failure hidden")
	}
	if m.State().Pending.Status != "rollback_failed" {
		t.Fatal("failed recovery not visible")
	}
	if _, err = m.Apply(req("change-blocked")); !errors.Is(err, ErrConflict) {
		t.Fatal("new apply during recovery")
	}
	b.failReplace = false
	if err = m.Tick(); err != nil || b.live.Exists || m.State().Pending != nil {
		t.Fatal("retry did not recover", err)
	}
}
func TestValidationAndDurabilityBeforeMutation(t *testing.T) {
	m, b, _ := testManager(t)
	b.failCheck = true
	if _, err := m.Apply(req("change-check")); err == nil || b.replaces != 0 {
		t.Fatal("changed kernel after invalid check")
	}
	b.failCheck = false
	realSave := m.save
	m.save = func(journal) error { return errors.New("disk full") }
	if _, err := m.Apply(req("change-disk")); err == nil || b.replaces != 0 {
		t.Fatal("changed kernel without durable intent")
	}
	m.save = realSave
	m.validateLAN = func() error { return errors.New("LAN down") }
	if _, err := m.Apply(req("change-lan")); err == nil || b.replaces != 0 {
		t.Fatal("missing LAN accepted")
	}
}
func TestAmbiguousNftFailureRestoresAndConfirmWriteFailureRemainsPending(t *testing.T) {
	m, b, _ := testManager(t)
	b.ambiguous = true
	if _, err := m.Apply(req("change-ambiguous")); err == nil || b.live.Exists {
		t.Fatal("uncertain kernel write not compensated")
	}
	r, err := m.Apply(req("change-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	save := m.save
	m.save = func(journal) error { return errors.New("disk full") }
	if _, err = m.Confirm(r.ID); err == nil || m.State().Pending == nil {
		t.Fatal("non-durable confirmation accepted")
	}
	m.save = save
	if err = m.Shutdown(); err != nil || b.live.Exists {
		t.Fatal("shutdown did not roll back", err)
	}
}
func TestCannotOpenConcurrentAgentAndCannotChangeLAN(t *testing.T) {
	m, b, dir := testManager(t)
	if other, err := NewManager(dir, b, m.safety); err == nil {
		other.Close()
		t.Fatal("concurrent agent allowed")
	}
	if _, err := m.Apply(req("change-lock")); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if other, err := NewManager(dir, b, policy.Safety{LANInterface: "wan0", ManagementPort: 8443}); err == nil {
		other.Close()
		t.Fatal("LAN silently changed across restart")
	}
}
func TestDriftBeforeConfirmRollsBack(t *testing.T) {
	m, b, _ := testManager(t)
	r, err := m.Apply(req("change-drift"))
	if err != nil {
		t.Fatal(err)
	}
	b.live.Rules += "# external drift\n"
	if _, err = m.Confirm(r.ID); !errors.Is(err, ErrConflict) || b.live.Exists {
		t.Fatal("drift confirmed", err)
	}
}
