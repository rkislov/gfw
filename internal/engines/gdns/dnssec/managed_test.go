// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"strings"
	"testing"
	"time"
)

func rootMessage(t *testing.T, now time.Time, keys []signer, signers ...signer) *dns.Msg {
	t.Helper()
	records := []dns.RR{}
	for _, key := range keys {
		records = append(records, dns.Copy(key.key))
	}
	answer := append([]dns.RR{}, records...)
	for _, key := range signers {
		sig := key.sign(t, records)
		sig.Inception = uint32(now.Add(-time.Hour).Unix())
		sig.Expiration = uint32(now.Add(48 * time.Hour).Unix())
		if err := sig.Sign(key.private, records); err != nil {
			t.Fatal(err)
		}
		answer = append(answer, sig)
	}
	return reply(".", dns.TypeDNSKEY, answer, nil, 0)
}
func revokeSigner(s signer) signer { k := *s.key; k.Flags |= 128; return signer{&k, s.private} }
func initialManaged(keys ...signer) ManagedState {
	s := ManagedState{Version: 1, Keys: []ManagedKey{}}
	for _, key := range keys {
		ds := key.key.ToDS(dns.SHA256)
		ds.Hdr.Ttl = 0
		s.Seeds = append(s.Seeds, ds.String())
	}
	return s
}
func stateOf(t *testing.T, s ManagedState, key signer) ManagedKey {
	t.Helper()
	for _, entry := range s.Keys {
		if entry.ID == keyID(key.key) {
			return entry
		}
	}
	return ManagedKey{State: "Start"}
}
func advance(t *testing.T, s ManagedState, now time.Time, msg *dns.Msg) ManagedState {
	t.Helper()
	next, err := transition(s, msg, now, DefaultConfig(), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = checkManagedState(next); err != nil {
		t.Fatal(err)
	}
	return next
}
func TestRFC5011AddHoldDownAndRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	s := advance(t, initialManaged(a), now, rootMessage(t, now, []signer{a, b}, a))
	if stateOf(t, s, a).State != Valid || stateOf(t, s, b).State != AddPending || !stateOf(t, s, b).AcceptAfter.Equal(now.Add(HoldDown)) {
		t.Fatal(s)
	}
	s = advance(t, s, now.Add(29*24*time.Hour), rootMessage(t, now.Add(29*24*time.Hour), []signer{a, b}, a))
	if stateOf(t, s, b).State != AddPending {
		t.Fatal("early acceptance")
	}
	restored := cloneManaged(s)
	if err := checkManagedState(restored); err != nil {
		t.Fatal(err)
	}
	later := now.Add(HoldDown + time.Second)
	if _, err := transition(restored, rootMessage(t, later, []signer{a, b}, b), later, DefaultConfig(), context.Background()); err == nil {
		t.Fatal("candidate authenticated itself before acceptance")
	}
	s = advance(t, restored, later, rootMessage(t, later, []signer{a, b}, a))
	if stateOf(t, s, b).State != Valid {
		t.Fatal("fresh post-hold RRset did not accept key")
	}
	s = advance(t, s, later.Add(time.Hour), rootMessage(t, later.Add(time.Hour), []signer{b}, b))
	if stateOf(t, s, a).State != Missing || len(effectiveRoots(s)) != 2 {
		t.Fatal("missing key lost trust")
	}
	s = advance(t, s, later.Add(2*time.Hour), rootMessage(t, later.Add(2*time.Hour), []signer{a, b}, b))
	if stateOf(t, s, a).State != Valid {
		t.Fatal("missing key did not return")
	}
}
func TestRFC5011AbsenceResetsCandidate(t *testing.T) {
	now := time.Now()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	s := advance(t, initialManaged(a), now, rootMessage(t, now, []signer{a, b}, a))
	s = advance(t, s, now.Add(20*24*time.Hour), rootMessage(t, now.Add(20*24*time.Hour), []signer{a}, a))
	if stateOf(t, s, b).State != "Start" {
		t.Fatal("absent candidate retained")
	}
	later := now.Add(31 * 24 * time.Hour)
	s = advance(t, s, later, rootMessage(t, later, []signer{a, b}, a))
	if stateOf(t, s, b).State != AddPending || !stateOf(t, s, b).AcceptAfter.Equal(later.Add(HoldDown)) {
		t.Fatal("old acceptance timer reused")
	}
}
func TestRFC5011SelfSignedRevocationAndPermanentTombstone(t *testing.T) {
	now := time.Now()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	revoked := revokeSigner(a)
	s := advance(t, initialManaged(a, b), now, rootMessage(t, now, []signer{a, b}, a))
	// Another trusted key cannot revoke A by changing A's flags.
	s = advance(t, s, now.Add(time.Hour), rootMessage(t, now.Add(time.Hour), []signer{revoked, b}, b))
	if stateOf(t, s, a).State == Revoked {
		t.Fatal("cross-signed revocation accepted")
	}
	s = advance(t, s, now.Add(2*time.Hour), rootMessage(t, now.Add(2*time.Hour), []signer{revoked, b}, revoked, b))
	if stateOf(t, s, a).State != Revoked || len(effectiveRoots(s)) != 1 {
		t.Fatal("self-revocation not immediate")
	}
	absent := now.Add(3 * time.Hour)
	s = advance(t, s, absent, rootMessage(t, absent, []signer{b}, b))
	s = advance(t, s, absent.Add(HoldDown), rootMessage(t, absent.Add(HoldDown), []signer{b}, b))
	if stateOf(t, s, a).State != Removed {
		t.Fatal("remove hold-down not applied")
	}
	later := absent.Add(HoldDown + time.Hour)
	s = advance(t, s, later, rootMessage(t, later, []signer{a, b}, b))
	if stateOf(t, s, a).State != Removed || len(effectiveRoots(s)) != 1 {
		t.Fatal("revoked key resurrected")
	}
	if _, err := transition(s, rootMessage(t, later, []signer{a, b}, a), later, DefaultConfig(), context.Background()); err == nil {
		t.Fatal("removed key authenticated an RRset")
	}
}
func TestRFC5011RevocationOnlyCancelsCompromisedIntroduction(t *testing.T) {
	now := time.Now()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	s := advance(t, initialManaged(a), now, rootMessage(t, now, []signer{a, b}, a))
	later := now.Add(HoldDown + time.Hour)
	revoked := revokeSigner(a)
	s = advance(t, s, later, rootMessage(t, later, []signer{revoked, b}, revoked))
	if stateOf(t, s, a).State != Revoked || stateOf(t, s, b).State != "Start" || len(effectiveRoots(s)) != 0 {
		t.Fatal("compromised introducer promoted replacement", s)
	}
	if _, err := NewWithRootAnchors(DefaultConfig(), effectiveRoots(s)); err != nil {
		t.Fatal(err)
	}
	v, _ := NewWithRootAnchors(DefaultConfig(), nil)
	run := &validationRun{v: v, ctx: context.Background(), memo: map[string]zoneState{}}
	if _, err := run.state(".", 0); err == nil {
		t.Fatal("empty managed set restored default roots")
	}
}
func TestRFC5011OriginalIntroducerRevocationRestartsTimer(t *testing.T) {
	now := time.Now()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	c := newSigner(t, ".")
	s := advance(t, initialManaged(a, c), now, rootMessage(t, now, []signer{a, b, c}, a))
	later := now.Add(HoldDown + time.Hour)
	revoked := revokeSigner(a)
	s = advance(t, s, later, rootMessage(t, later, []signer{revoked, b, c}, revoked, c))
	if stateOf(t, s, b).State != AddPending || !stateOf(t, s, b).AcceptAfter.Equal(later.Add(HoldDown)) {
		t.Fatal("revoked original signer did not cancel timer")
	}
}
func TestRFC5011RefreshIntervals(t *testing.T) {
	for _, tc := range []struct {
		ttl        uint32
		expiration time.Duration
		cap        int
		retry      bool
		want       time.Duration
	}{{172800, 10 * 24 * time.Hour, 24, false, 24 * time.Hour}, {1800, 24 * time.Hour, 24, false, time.Hour}, {100 * 86400, 100 * 24 * time.Hour, 360, false, 15 * 24 * time.Hour}, {172800, 10 * 24 * time.Hour, 24, true, 288 * time.Minute}, {0, 0, 24, true, time.Hour}} {
		if got := refreshInterval(tc.ttl, tc.expiration, tc.cap, tc.retry); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	now := time.Now()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	a.key.Hdr.Ttl = 40 * 86400
	b.key.Hdr.Ttl = 40 * 86400
	s := advance(t, initialManaged(a), now, rootMessage(t, now, []signer{a, b}, a))
	if !stateOf(t, s, b).AcceptAfter.Equal(now.Add(40 * 24 * time.Hour)) {
		t.Fatal("original TTL ignored")
	}
}
func TestRFC5011ManagerDurabilityRetryAndClock(t *testing.T) {
	now := time.Now().UTC()
	a := newSigner(t, ".")
	b := newSigner(t, ".")
	var disk *ManagedState
	fail := false
	calls := 0
	load := func(context.Context) (*ManagedState, error) {
		if disk == nil {
			return nil, nil
		}
		s := cloneManaged(*disk)
		return &s, nil
	}
	save := func(_ context.Context, s ManagedState) (int64, error) {
		if fail && s.LastSuccess.Equal(now) {
			return 0, errors.New("disk unavailable")
		}
		s.Revision++
		disk = &s
		return s.Revision, nil
	}
	c := DefaultConfig()
	c.AutoUpdate.Enabled = true
	c.TrustAnchors = initialManaged(a).Seeds
	m, err := OpenManager(context.Background(), load, save)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	fetch := func(context.Context, string, uint16) (*dns.Msg, error) {
		calls++
		return rootMessage(t, now, []signer{a, b}, a), nil
	}
	if err = m.Refresh(context.Background(), c, fetch); err != nil {
		t.Fatal(err)
	}
	if err = m.Refresh(context.Background(), c, fetch); err != nil || calls != 1 {
		t.Fatal("probe minimum interval bypassed", calls, err)
	}
	restored, err := OpenManager(context.Background(), load, save)
	if err != nil {
		t.Fatal(err)
	}
	restored.now = func() time.Time { return now }
	if err = restored.Refresh(context.Background(), c, fetch); err != nil || calls != 1 {
		t.Fatal("restart reset probe schedule")
	}
	fail = true
	now = now.Add(HoldDown + time.Hour)
	if err = restored.Refresh(context.Background(), c, fetch); err == nil {
		t.Fatal("persistence failure ignored")
	}
	roots, initialized := restored.Roots()
	if !initialized || len(roots) != 0 || restored.Status(c).State != "storage_error" {
		t.Fatal("unpersisted trust published")
	}
	fail = false
	now = now.Add(time.Minute)
	if err = restored.Refresh(context.Background(), c, fetch); err != nil {
		t.Fatal(err)
	}
	if roots, _ = restored.Roots(); len(roots) != 2 {
		t.Fatal("pending durable update not recovered")
	}
	now = now.Add(-2 * HoldDown)
	if err = restored.Refresh(context.Background(), c, fetch); err == nil || restored.Status(c).State != "clock_error" {
		t.Fatal("clock rollback accepted")
	}
	c.AutoUpdate.Enabled = false
	if err = restored.Refresh(context.Background(), c, fetch); err != nil {
		t.Fatal(err)
	}
	if roots, _ = restored.Roots(); len(roots) != 2 {
		t.Fatal("pausing dropped learned anchors")
	}
	c.TrustAnchors = append(c.TrustAnchors, RootAnchors[0])
	if err = restored.CheckSeeds(c); err == nil {
		t.Fatal("root seed reset accepted")
	}
	bad := cloneManaged(*disk)
	bad.Keys[0].State = "Bad"
	if _, err = OpenManager(context.Background(), func(context.Context) (*ManagedState, error) { return &bad, nil }, save); err == nil {
		t.Fatal("corrupt state silently bootstrapped")
	}
	if strings.Join(RootSeeds(DefaultConfig()), "\n") == "" {
		t.Fatal("missing bootstrap roots")
	}
}

func TestRFC5011UnauthenticatedRevocationDoesNotCountAsSuccess(t *testing.T) {
	now := time.Now()
	a := newSigner(t, ".")
	attacker := revokeSigner(newSigner(t, "."))
	s := initialManaged(a)
	if _, err := transition(s, rootMessage(t, now, []signer{attacker}, attacker), now, DefaultConfig(), context.Background()); err == nil {
		t.Fatal("unrelated revoked key authenticated a root observation")
	}
}

func TestRFC5011FailedProbeIsDurableAndIntervalSettingApplies(t *testing.T) {
	now := time.Now().UTC()
	a := newSigner(t, ".")
	var disk *ManagedState
	c := DefaultConfig()
	c.TrustAnchors = initialManaged(a).Seeds
	c.AutoUpdate.Enabled = true
	load := func(context.Context) (*ManagedState, error) {
		if disk == nil {
			return nil, nil
		}
		s := cloneManaged(*disk)
		return &s, nil
	}
	save := func(_ context.Context, s ManagedState) (int64, error) {
		s.Revision++
		disk = &s
		return s.Revision, nil
	}
	m, _ := OpenManager(context.Background(), load, save)
	m.now = func() time.Time { return now }
	calls := 0
	fetch := func(ctx context.Context, _ string, _ uint16) (*dns.Msg, error) {
		calls++
		if disk.LastAttempt != now || disk.NextProbe.Before(now.Add(time.Hour)) {
			t.Fatal("probe schedule not persisted before IO")
		}
		return rootMessage(t, now, []signer{a}, a), nil
	}
	if err := m.Refresh(context.Background(), c, fetch); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	c.AutoUpdate.RefreshHours = 1
	if err := m.Refresh(context.Background(), c, fetch); err != nil || calls != 2 {
		t.Fatal("changed refresh cap not applied", err, calls)
	}
	now = now.Add(2 * time.Hour)
	fetch = func(ctx context.Context, _ string, _ uint16) (*dns.Msg, error) {
		calls++
		if disk.LastAttempt != now || disk.NextProbe.Before(now.Add(time.Hour)) {
			t.Fatal("attempt cooldown not durable")
		}
		return nil, context.DeadlineExceeded
	}
	if err := m.Refresh(context.Background(), c, fetch); err == nil {
		t.Fatal("network error hidden")
	}
	if roots, _ := m.Roots(); len(roots) != 1 || m.Status(c).State != "error" {
		t.Fatal("network error discarded existing trust")
	}
	restored, err := OpenManager(context.Background(), load, save)
	if err != nil {
		t.Fatal(err)
	}
	restored.now = func() time.Time { return now.Add(30 * time.Minute) }
	if err = restored.Refresh(context.Background(), c, fetch); err != nil || calls != 3 {
		t.Fatal("restart bypassed failed attempt cooldown", err, calls)
	}
}

func TestRFC5011RejectsBogusRootObservations(t *testing.T) {
	for _, scenario := range []string{"tamper", "unsigned-ad", "expired", "future"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			a := newSigner(t, ".")
			b := newSigner(t, ".")
			msg := rootMessage(t, now, []signer{a, b}, a)
			switch scenario {
			case "tamper":
				msg.Answer[1].(*dns.DNSKEY).PublicKey = a.key.PublicKey
			case "unsigned-ad":
				msg.Answer = msg.Answer[:2]
				msg.AuthenticatedData = true
			case "expired":
				msg.Answer[2].(*dns.RRSIG).Expiration = uint32(now.Add(-time.Hour).Unix())
			case "future":
				msg.Answer[2].(*dns.RRSIG).Inception = uint32(now.Add(time.Hour).Unix())
			}
			if _, err := transition(initialManaged(a), msg, now, DefaultConfig(), context.Background()); err == nil {
				t.Fatal("bogus root observation accepted")
			}
		})
	}
}

func TestRFC5011InterruptedProbeDoesNotRestoreUncertainTrust(t *testing.T) {
	now := time.Now().UTC()
	a := newSigner(t, ".")
	state := advance(t, initialManaged(a), now.Add(-time.Hour), rootMessage(t, now.Add(-time.Hour), []signer{a}, a))
	state.Revision = 1
	state.ProbeInProgress = true
	state.LastAttempt = now
	state.UpdatedAt = now
	state.NextProbe = now.Add(time.Hour)
	state.RefreshHours = 24
	load := func(context.Context) (*ManagedState, error) { return managedCopy(state), nil }
	save := func(_ context.Context, s ManagedState) (int64, error) {
		s.Revision++
		state = s
		return s.Revision, nil
	}
	m, err := OpenManager(context.Background(), load, save)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	c := DefaultConfig()
	c.TrustAnchors = state.Seeds
	c.AutoUpdate.Enabled = true
	if roots, _ := m.Roots(); len(roots) != 0 || m.Status(c).State != "recovery_required" {
		t.Fatal("interrupted observation restored previous trust")
	}
	calls := 0
	fetch := func(context.Context, string, uint16) (*dns.Msg, error) { calls++; return nil, context.DeadlineExceeded }
	if err = m.Refresh(context.Background(), c, fetch); err != nil || calls != 0 {
		t.Fatal("recovery bypassed durable cooldown")
	}
	now = now.Add(time.Hour)
	if err = m.Refresh(context.Background(), c, fetch); err == nil {
		t.Fatal("failed recovery hidden")
	}
	if roots, _ := m.Roots(); len(roots) != 0 {
		t.Fatal("failed recovery restored uncertain trust")
	}
	now = now.Add(time.Hour)
	if err = m.Refresh(context.Background(), c, func(context.Context, string, uint16) (*dns.Msg, error) {
		return rootMessage(t, now, []signer{a}, a), nil
	}); err != nil {
		t.Fatal(err)
	}
	if roots, _ := m.Roots(); len(roots) != 1 || m.Status(c).State != "healthy" || state.ProbeInProgress {
		t.Fatal("authenticated recovery did not complete")
	}
}
