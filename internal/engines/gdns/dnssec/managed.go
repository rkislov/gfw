// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const HoldDown = 30 * 24 * time.Hour
const (
	AddPending = "AddPend"
	Valid      = "Valid"
	Missing    = "Missing"
	Revoked    = "Revoked"
	Removed    = "Removed"
)

type ManagedKey struct {
	ID              string    `json:"id"`
	Key             string    `json:"key"`
	Tag             uint16    `json:"tag"`
	State           string    `json:"state"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	AcceptAfter     time.Time `json:"accept_after,omitempty"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	MissingSince    time.Time `json:"missing_since,omitempty"`
	HoldDownSeconds int64     `json:"hold_down_seconds,omitempty"`
	Validators      []string  `json:"validators,omitempty"`
}
type ManagedState struct {
	ProbeInProgress   bool         `json:"probe_in_progress"`
	RefreshHours      int          `json:"refresh_hours"`
	ClockHoldUntil    time.Time    `json:"clock_hold_until"`
	Version           int          `json:"version"`
	Revision          int64        `json:"revision"`
	Seeds             []string     `json:"seeds"`
	Keys              []ManagedKey `json:"keys"`
	UpdatedAt         time.Time    `json:"updated_at"`
	LastAttempt       time.Time    `json:"last_attempt"`
	LastSuccess       time.Time    `json:"last_success"`
	NextProbe         time.Time    `json:"next_probe"`
	LastError         string       `json:"last_error,omitempty"`
	OriginalTTL       uint32       `json:"original_ttl"`
	ExpirationSeconds int64        `json:"expiration_seconds"`
}
type ManagedStatus struct {
	Initialized        bool         `json:"initialized"`
	Enabled            bool         `json:"enabled"`
	State              string       `json:"state"`
	LastAttempt        time.Time    `json:"last_attempt"`
	LastSuccess        time.Time    `json:"last_success"`
	NextProbe          time.Time    `json:"next_probe"`
	LastError          string       `json:"last_error,omitempty"`
	ActiveAnchors      int          `json:"active_anchors"`
	Keys               []ManagedKey `json:"keys"`
	AddHoldDownDays    int          `json:"add_hold_down_days"`
	RemoveHoldDownDays int          `json:"remove_hold_down_days"`
}
type ManagedLoad func(context.Context) (*ManagedState, error)
type ManagedSave func(context.Context, ManagedState) (int64, error)
type Manager struct {
	mu                sync.RWMutex
	state             *ManagedState
	pending           *ManagedState
	save              ManagedSave
	storageError      string
	revocationBarrier func()
	now               func() time.Time
	// liveTime keeps Go's monotonic component; serialized timestamps never do.
	liveTime time.Time
	wake     chan struct{}
}

func OpenManager(ctx context.Context, load ManagedLoad, save ManagedSave) (*Manager, error) {
	s, err := load(ctx)
	if err != nil {
		return nil, err
	}
	if s != nil {
		if err = checkManagedState(*s); err != nil {
			return nil, err
		}
	}
	manager := &Manager{state: managedCopyNullable(s), save: save, now: time.Now, wake: make(chan struct{}, 1)}
	if s != nil && s.ProbeInProgress {
		manager.storageError = "unfinished RFC 5011 observation; waiting for an authenticated recovery probe"
	}
	return manager, nil
}
func (m *Manager) persist(ctx context.Context, s ManagedState) (int64, error) {
	durable, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return m.save(durable, s)
}

// The barrier is an in-memory, nonblocking notification. It closes the window
// between authenticating a revocation and committing it to persistent storage.
func (m *Manager) SetRevocationBarrier(barrier func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revocationBarrier = barrier
}
func (m *Manager) revokeBarrier(old, next ManagedState) {
	states := map[string]string{}
	for _, key := range old.Keys {
		states[key.ID] = key.State
	}
	for _, key := range next.Keys {
		if key.State == Revoked && states[key.ID] != Revoked && states[key.ID] != Removed {
			if m.revocationBarrier != nil {
				m.revocationBarrier()
			}
			return
		}
	}
}
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}
func (m *Manager) Run(ctx context.Context, refresh func(context.Context) error) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		_ = refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
	}
}
func cloneManaged(s ManagedState) ManagedState {
	b, _ := json.Marshal(s)
	var out ManagedState
	_ = json.Unmarshal(b, &out)
	return out
}
func managedCopy(s ManagedState) *ManagedState { copy := cloneManaged(s); return &copy }
func managedCopyNullable(s *ManagedState) *ManagedState {
	if s == nil {
		return nil
	}
	return managedCopy(*s)
}
func RootSeeds(c Config) []string {
	out := []string{}
	for _, line := range c.TrustAnchors {
		rr, err := dns.NewRR(line)
		if err == nil && canonical(rr.Header().Name) == "." {
			rr.Header().Ttl = 0
			out = append(out, rr.String())
		}
	}
	sort.Strings(out)
	return out
}
func (m *Manager) CheckSeeds(c Config) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state != nil && strings.Join(RootSeeds(c), "\n") != strings.Join(m.state.Seeds, "\n") {
		return fmt.Errorf("RFC 5011 root bootstrap anchors are already initialized; preserve root entries (private anchors remain editable)")
	}
	return nil
}
func keyID(k *dns.DNSKEY) string {
	c := *k
	c.Flags &^= 128
	c.Hdr.Ttl = 0
	c.Hdr.Name = "."
	sum := sha256.Sum256([]byte(c.String()))
	return hex.EncodeToString(sum[:])
}
func usableSEP(k *dns.DNSKEY) bool {
	return k.Hdr.Name == "." && k.Hdr.Class == dns.ClassINET && k.Protocol == 3 && k.Flags&257 == 257 && k.Flags & ^uint16(385) == 0 && supportedKey(k)
}
func supportedKey(k *dns.DNSKEY) bool {
	// Keep managed rollover limited to algorithms whose self-signatures can be
	// checked by dns.RRSIG.Verify (which deliberately performs no wall-clock IO).
	switch k.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
	default:
		return false
	}
	copyKey := *k
	copyKey.Flags &^= 128
	c := DefaultConfig()
	c.TrustAnchors = []string{copyKey.String()}
	_, err := Normalize(c)
	return err == nil
}
func seedMatches(line string, k *dns.DNSKEY) bool {
	rr, err := dns.NewRR(line)
	if err != nil {
		return false
	}
	copyKey := *k
	copyKey.Flags &^= 128
	switch anchor := rr.(type) {
	case *dns.DNSKEY:
		return keyID(anchor) == keyID(&copyKey)
	case *dns.DS:
		ds := copyKey.ToDS(anchor.DigestType)
		return ds != nil && ds.KeyTag == anchor.KeyTag && ds.Algorithm == anchor.Algorithm && strings.EqualFold(ds.Digest, anchor.Digest)
	}
	return false
}
func effectiveRoots(s ManagedState) []string {
	out := []string{}
	for _, line := range s.Seeds {
		known := false
		for _, entry := range s.Keys {
			rr, _ := dns.NewRR(entry.Key)
			if seedMatches(line, rr.(*dns.DNSKEY)) {
				known = true
				break
			}
		}
		if !known {
			out = append(out, line)
		}
	}
	for _, entry := range s.Keys {
		if entry.State == Valid || entry.State == Missing {
			out = append(out, entry.Key)
		}
	}
	sort.Strings(out)
	return out
}
func (m *Manager) Roots() ([]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil {
		return nil, false
	}
	if m.storageError != "" {
		return []string{}, true
	}
	return effectiveRoots(*m.state), true
}
func (m *Manager) Status(c Config) ManagedStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := ManagedStatus{Enabled: c.AutoUpdate.Enabled, State: "disabled", Keys: []ManagedKey{}, AddHoldDownDays: 30, RemoveHoldDownDays: 30}
	if m.state == nil {
		if m.storageError != "" {
			out.State = "storage_error"
			out.LastError = m.storageError
			return out
		}
		if out.Enabled {
			out.State = "waiting"
		}
		return out
	}
	s := cloneManaged(*m.state)
	out.Initialized = true
	out.Keys = s.Keys
	out.LastAttempt = s.LastAttempt
	out.LastSuccess = s.LastSuccess
	out.NextProbe = s.NextProbe
	out.LastError = s.LastError
	out.ActiveAnchors = len(effectiveRoots(s))
	out.State = "healthy"
	if s.LastSuccess.IsZero() {
		out.State = "waiting"
	}
	if !out.Enabled {
		out.State = "paused"
	}
	if s.LastError != "" {
		out.State = "error"
	}
	if out.ActiveAnchors == 0 {
		out.State = "trust_lost"
	}
	if m.storageError != "" {
		out.State = "storage_error"
		if s.ProbeInProgress && m.pending == nil {
			out.State = "recovery_required"
		}
		out.LastError = m.storageError
		out.ActiveAnchors = 0
	}
	if m.now().Before(s.UpdatedAt) {
		out.State = "clock_error"
	}
	return out
}
func checkManagedState(s ManagedState) error {
	if s.Version != 1 || len(s.Seeds) == 0 || len(s.Seeds) > 64 || len(s.Keys) > 512 {
		return fmt.Errorf("invalid RFC 5011 persisted state")
	}
	c := DefaultConfig()
	c.TrustAnchors = s.Seeds
	if _, err := Normalize(c); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range s.Keys {
		rr, err := dns.NewRR(entry.Key)
		if err != nil {
			return err
		}
		k, ok := rr.(*dns.DNSKEY)
		if !ok || !usableSEP(k) || k.Flags&128 != 0 || entry.ID != keyID(k) || seen[entry.ID] {
			return fmt.Errorf("invalid RFC 5011 key identity")
		}
		seen[entry.ID] = true
		switch entry.State {
		case AddPending, Valid, Missing, Revoked, Removed:
		default:
			return fmt.Errorf("invalid RFC 5011 key state")
		}
		if entry.FirstSeen.IsZero() || (entry.State == AddPending && (entry.AcceptAfter.Before(entry.FirstSeen.Add(HoldDown)) || len(entry.Validators) == 0 || entry.HoldDownSeconds < int64(HoldDown/time.Second))) || ((entry.State == Revoked || entry.State == Removed) && entry.RevokedAt.IsZero()) {
			return fmt.Errorf("invalid RFC 5011 timer")
		}
	}
	return nil
}

// authenticateRoot validates each candidate signature directly against a trusted
// key. Revocation is the exception: a revoked key MUST self-sign the full RRset,
// even when no surviving trust anchor can authenticate it.
func authenticateRoot(ctx context.Context, s ManagedState, msg *dns.Msg, now time.Time) (map[string]bool, map[string]bool, []*dns.DNSKEY, uint32, time.Duration, error) {
	if msg == nil || !msg.Response || msg.Truncated || msg.Rcode != 0 || len(msg.Question) != 1 || msg.Question[0].Name != "." || msg.Question[0].Qtype != dns.TypeDNSKEY || msg.Question[0].Qclass != dns.ClassINET || len(msg.Answer) > 128 {
		return nil, nil, nil, 0, 0, fmt.Errorf("invalid root DNSKEY response")
	}
	records := rrset(msg.Answer, ".", dns.TypeDNSKEY)
	sigs := signatures(msg.Answer, ".", dns.TypeDNSKEY)
	if len(records) == 0 || len(records) > 64 || len(sigs) > 32 {
		return nil, nil, nil, 0, 0, fmt.Errorf("invalid root DNSKEY RRset size")
	}
	keys := []*dns.DNSKEY{}
	for _, rr := range records {
		k := rr.(*dns.DNSKEY)
		if k.Hdr.Class != dns.ClassINET {
			return nil, nil, nil, 0, 0, fmt.Errorf("non-IN root key")
		}
		if usableSEP(k) {
			keys = append(keys, k)
		}
	}
	trusted := map[string]bool{}
	known := map[string]string{}
	for _, entry := range s.Keys {
		known[entry.ID] = entry.State
		if entry.State == Valid || entry.State == Missing {
			trusted[entry.ID] = true
		}
	}
	for _, k := range keys {
		id := keyID(k)
		if _, exists := known[id]; !exists {
			for _, seed := range s.Seeds {
				if seedMatches(seed, k) {
					trusted[id] = true
				}
			}
		}
	}
	validating := map[string]bool{}
	revocations := map[string]bool{}
	ttl := uint32(^uint32(0))
	expiration := 15 * 24 * time.Hour
	work := 0
	for _, rr := range sigs {
		sig := rr.(*dns.RRSIG)
		if sig.Hdr.Class != dns.ClassINET || sig.SignerName != "." || !sig.ValidityPeriod(now) {
			continue
		}
		for _, k := range keys {
			if err := ctx.Err(); err != nil {
				return nil, nil, nil, 0, 0, err
			}
			id := keyID(k)
			revoked := k.Flags&128 != 0
			if revoked && known[id] == "" && !trusted[id] {
				continue
			}
			if (!revoked && !trusted[id]) || sig.KeyTag != k.KeyTag() || sig.Algorithm != k.Algorithm {
				continue
			}
			work++
			if work > 128 {
				return nil, nil, nil, 0, 0, fmt.Errorf("RFC 5011 signature budget exceeded")
			}
			if sig.Verify(k, records) != nil {
				continue
			}
			if revoked {
				revocations[id] = true
				continue
			}
			validating[id] = true
			if sig.OrigTtl < ttl {
				ttl = sig.OrigTtl
			}
			if d := time.Unix(int64(sig.Expiration), 0).Sub(now); d < expiration {
				expiration = d
			}
		}
	}
	if len(validating) == 0 && len(revocations) == 0 {
		return nil, nil, nil, 0, 0, fmt.Errorf("root DNSKEY RRset was not authenticated by an existing anchor")
	}
	return validating, revocations, keys, ttl, expiration, nil
}
func refreshInterval(ttl uint32, expiration time.Duration, capHours int, retry bool) time.Duration {
	limit := 15 * 24 * time.Hour
	divisor := 2
	cap := time.Duration(capHours) * time.Hour
	if retry {
		limit = 24 * time.Hour
		divisor = 10
	}
	interval := min(limit, time.Duration(ttl)*time.Second/time.Duration(divisor), expiration/time.Duration(divisor), cap)
	return max(time.Hour, interval)
}
func transition(s ManagedState, msg *dns.Msg, now time.Time, c Config, ctx context.Context) (ManagedState, error) {
	validators, revocations, keys, ttl, expiration, err := authenticateRoot(ctx, s, msg, now)
	if err != nil {
		return s, err
	}
	out := cloneManaged(s)
	historyFull := false
	presentAll := map[string]bool{}
	for _, key := range keys {
		presentAll[keyID(key)] = true
	}
	byID := map[string]int{}
	present := map[string]bool{}
	for i, k := range out.Keys {
		byID[k.ID] = i
	}
	// Revoke before considering additions; a compromised introducer cannot revoke
	// itself and simultaneously finish introducing its replacement.
	for _, k := range keys {
		id := keyID(k)
		if !revocations[id] {
			continue
		}
		i, exists := byID[id]
		if !exists {
			recognized := false
			for _, seed := range s.Seeds {
				recognized = recognized || seedMatches(seed, k)
			}
			if !recognized {
				continue
			}
			copyKey := *k
			copyKey.Flags &^= 128
			out.Keys = append(out.Keys, ManagedKey{ID: id, Key: copyKey.String(), Tag: copyKey.KeyTag(), State: Valid, FirstSeen: now})
			i = len(out.Keys) - 1
			byID[id] = i
		}
		entry := &out.Keys[i]
		if entry.State != Revoked && entry.State != Removed {
			entry.State = Revoked
			entry.RevokedAt = now
			entry.MissingSince = time.Time{}
		}
		entry.LastSeen = now
	}
	survivors := map[string]bool{}
	for id := range validators {
		i, known := byID[id]
		if !known || (out.Keys[i].State != Revoked && out.Keys[i].State != Removed) {
			survivors[id] = true
		}
	}
	if len(survivors) > 0 {
		for _, k := range keys {
			if k.Flags&128 != 0 {
				continue
			}
			id := keyID(k)
			present[id] = true
			i, exists := byID[id]
			if !exists {
				state := AddPending
				for _, seed := range s.Seeds {
					if seedMatches(seed, k) {
						state = Valid
						break
					}
				}
				if state == AddPending && len(out.Keys) >= 512-len(out.Seeds) {
					historyFull = true
					continue
				}
				v := []string{}
				for signer := range survivors {
					v = append(v, signer)
				}
				sort.Strings(v)
				out.Keys = append(out.Keys, ManagedKey{ID: id, Key: k.String(), Tag: k.KeyTag(), State: state, FirstSeen: now, LastSeen: now, AcceptAfter: now.Add(max(HoldDown, time.Duration(ttl)*time.Second)), HoldDownSeconds: int64(max(HoldDown, time.Duration(ttl)*time.Second) / time.Second), Validators: v})
				byID[id] = len(out.Keys) - 1
				continue
			}
			entry := &out.Keys[i]
			entry.LastSeen = now
			switch entry.State {
			case Missing:
				entry.State = Valid
				entry.MissingSince = time.Time{}
			case AddPending:
				originalSurvives := false
				for _, signer := range entry.Validators {
					j, known := byID[signer]
					if !known || (out.Keys[j].State != Revoked && out.Keys[j].State != Removed) {
						originalSurvives = true
					}
				}
				if !originalSurvives {
					entry.FirstSeen = now
					entry.AcceptAfter = now.Add(max(HoldDown, time.Duration(ttl)*time.Second))
					entry.HoldDownSeconds = int64(max(HoldDown, time.Duration(ttl)*time.Second) / time.Second)
					entry.Validators = nil
					for signer := range survivors {
						entry.Validators = append(entry.Validators, signer)
					}
					sort.Strings(entry.Validators)
				} else if !now.Before(entry.AcceptAfter) && now.After(entry.FirstSeen) {
					entry.State = Valid
				}
			}
		}
		kept := []ManagedKey{}
		for _, entry := range out.Keys {
			if !present[entry.ID] {
				switch entry.State {
				case AddPending:
					continue
				case Valid:
					entry.State = Missing
					entry.MissingSince = now
				}
			}
			if entry.State == Revoked {
				if presentAll[entry.ID] {
					entry.LastSeen = now
					entry.MissingSince = time.Time{}
				} else {
					if entry.MissingSince.IsZero() {
						entry.MissingSince = now
					}
					if !now.Before(entry.MissingSince.Add(HoldDown)) {
						entry.State = Removed
					}
				}
			}
			kept = append(kept, entry)
		}
		out.Keys = kept
	}
	// Even a revocation-only RRset permanently cancels introductions whose entire
	// original signer set has been revoked. It cannot introduce new keys.
	states := map[string]string{}
	for _, entry := range out.Keys {
		states[entry.ID] = entry.State
	}
	kept := []ManagedKey{}
	for _, entry := range out.Keys {
		if entry.State == AddPending {
			alive := false
			for _, id := range entry.Validators {
				if states[id] != Revoked && states[id] != Removed {
					alive = true
				}
			}
			if !alive {
				continue
			}
		}
		kept = append(kept, entry)
	}
	out.Keys = kept

	if len(out.Keys) > 512 {
		return s, fmt.Errorf("RFC 5011 key history limit reached")
	}
	out.LastSuccess = now
	out.LastError = ""
	if historyFull {
		out.LastError = "RFC 5011 key history capacity reached; new candidates ignored"
	}
	out.OriginalTTL = ttl
	out.ExpirationSeconds = int64(expiration / time.Second)
	out.NextProbe = now.Add(refreshInterval(ttl, expiration, c.AutoUpdate.RefreshHours, false))
	if len(survivors) == 0 {
		out.LastError = "root revocation authenticated; no surviving signature for additions"
		out.NextProbe = now.Add(time.Hour)
	}
	return out, nil
}

// Refresh is called under the engine's configuration-update lock. No SQL or
// manager locks occur on the ordinary DNS request path; newly observed
// revocations use ObserveRevocation to persist the security transition.
func (m *Manager) Refresh(ctx context.Context, c Config, fetch Fetch) error {
	if !c.AutoUpdate.Enabled {
		return nil
	}
	now := m.now()
	m.mu.Lock()
	if m.pending != nil {
		revision, err := m.persist(ctx, *m.pending)
		if err != nil {
			m.storageError = "RFC 5011 state persistence failed"
			m.mu.Unlock()
			return err
		}
		m.pending.Revision = revision
		m.state = m.pending
		m.pending = nil
		m.storageError = ""
		if m.state.ProbeInProgress {
			m.storageError = "unfinished RFC 5011 observation; waiting for an authenticated recovery probe"
		}
	}
	if m.state == nil {
		s := ManagedState{Version: 1, Seeds: RootSeeds(c), Keys: []ManagedKey{}, UpdatedAt: now, RefreshHours: c.AutoUpdate.RefreshHours}
		revision, err := m.persist(ctx, s)
		if err != nil {
			m.storageError = "RFC 5011 initialization persistence failed"
			m.mu.Unlock()
			return err
		}
		s.Revision = revision
		m.state = managedCopy(s)
	}
	s := cloneManaged(*m.state)
	uncertain := s.ProbeInProgress && m.storageError != ""
	if now.Before(s.UpdatedAt) {
		m.mu.Unlock()
		return fmt.Errorf("RFC 5011 clock moved backwards; timers are suspended")
	}
	// Detect wall-clock discontinuities during this process using monotonic time.
	if !m.liveTime.IsZero() {
		wall := now.Round(0).Sub(m.liveTime.Round(0))
		elapsed := now.Sub(m.liveTime)
		if delta := wall - elapsed; delta > 5*time.Minute || delta < -5*time.Minute {
			for i := range s.Keys {
				if s.Keys[i].State == AddPending {
					s.Keys[i].FirstSeen = now
					s.Keys[i].AcceptAfter = now.Add(max(HoldDown, time.Duration(s.Keys[i].HoldDownSeconds)*time.Second))
				}
			}
			s.ClockHoldUntil = now.Add(time.Hour)
			s.NextProbe = maxTime(s.NextProbe, s.ClockHoldUntil)
			s.UpdatedAt = now
			revision, err := m.persist(ctx, s)
			if err != nil {
				m.pending = &s
				m.storageError = "RFC 5011 clock reset persistence failed"
				m.mu.Unlock()
				return err
			}
			s.Revision = revision
			m.state = managedCopy(s)
		}
	}
	m.liveTime = now
	if s.RefreshHours != c.AutoUpdate.RefreshHours {
		if !s.LastAttempt.IsZero() {
			limit := s.LastAttempt.Add(refreshInterval(s.OriginalTTL, time.Duration(s.ExpirationSeconds)*time.Second, c.AutoUpdate.RefreshHours, s.LastError != ""))
			if limit.Before(s.NextProbe) {
				s.NextProbe = maxTime(limit, s.ClockHoldUntil)
			}
		}
		s.RefreshHours = c.AutoUpdate.RefreshHours
		revision, err := m.persist(ctx, s)
		if err != nil {
			m.pending = &s
			m.storageError = "RFC 5011 schedule persistence failed"
			m.mu.Unlock()
			return err
		}
		s.Revision = revision
		m.state = managedCopy(s)
	}
	if now.Before(s.NextProbe) {
		m.mu.Unlock()
		return nil
	}
	// Persist the attempt BEFORE network I/O so a crash cannot reset the
	// mandatory one-hour lower bound on queries.
	s.LastAttempt = now
	s.UpdatedAt = now
	s.ProbeInProgress = true
	s.NextProbe = now.Add(time.Hour)
	revision, attemptErr := m.persist(ctx, s)
	if attemptErr != nil {
		m.pending = &s
		m.storageError = "RFC 5011 probe schedule persistence failed"
		m.mu.Unlock()
		return attemptErr
	}
	s.Revision = revision
	m.state = managedCopy(s)
	m.mu.Unlock()
	if err := m.CheckSeeds(c); err != nil {
		return err
	}
	msg, err := fetch(ctx, ".", dns.TypeDNSKEY)
	if err == nil {
		s, err = transition(s, msg, now, c, ctx)
	}
	if err != nil {
		s.LastError = err.Error()
		s.NextProbe = now.Add(refreshInterval(s.OriginalTTL, time.Duration(s.ExpirationSeconds)*time.Second, c.AutoUpdate.RefreshHours, true))
	}
	s.LastAttempt = now
	s.UpdatedAt = now
	s.ProbeInProgress = uncertain && err != nil
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeBarrier(*m.state, s)
	revision, persistErr := m.persist(ctx, s)
	if persistErr != nil {
		m.pending = &s
		m.storageError = "RFC 5011 state persistence failed; managed validation is blocked"
		return persistErr
	}
	s.Revision = revision
	m.state = managedCopy(s)
	m.storageError = ""
	if s.ProbeInProgress {
		m.storageError = "unfinished RFC 5011 observation; waiting for an authenticated recovery probe"
	}
	return err
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// NeedsRevocation avoids SQL and the update mutex for ordinary DNSKEY responses.
// It is called only on freshly received root DNSKEY packets, never cache hits.
func (m *Manager) NeedsRevocation(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) != 1 || msg.Question[0].Name != "." || msg.Question[0].Qtype != dns.TypeDNSKEY {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil {
		return false
	}
	for _, rr := range msg.Answer {
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Flags&128 == 0 || !usableSEP(key) {
			continue
		}
		id := keyID(key)
		known := false
		for _, entry := range m.state.Keys {
			if entry.ID == id {
				known = true
				if entry.State != Revoked && entry.State != Removed {
					return true
				}
				break
			}
		}
		if !known {
			for _, seed := range m.state.Seeds {
				if seedMatches(seed, key) {
					return true
				}
			}
		}
	}
	return false
}

// ObserveRevocation processes a passive, fresh observation without issuing any
// query or moving the active-refresh schedule. Even paused polling must honor it.
func (m *Manager) ObserveRevocation(ctx context.Context, c Config, msg *dns.Msg) error {
	if !m.NeedsRevocation(msg) {
		return nil
	}
	now := m.now()
	m.mu.Lock()
	s := cloneManaged(*m.state)
	if m.pending != nil {
		s = cloneManaged(*m.pending)
	}
	uncertain := s.ProbeInProgress && m.storageError != ""
	// A durable intent prevents a crash or failed final write from restoring
	// the pre-observation trust set silently on the next startup.
	s.ProbeInProgress = true
	revision, err := m.persist(ctx, s)
	if err != nil {
		m.pending = &s
		m.storageError = "RFC 5011 observation intent persistence failed"
		m.mu.Unlock()
		return err
	}
	s.Revision = revision
	m.state = managedCopy(s)
	m.mu.Unlock()
	next, observationErr := transition(s, msg, now, c, ctx)
	if observationErr != nil {
		next = cloneManaged(s)
		next.LastError = observationErr.Error()
	}
	next.LastAttempt = s.LastAttempt
	next.NextProbe = s.NextProbe
	next.UpdatedAt = maxTime(now, s.UpdatedAt)
	next.ProbeInProgress = uncertain && observationErr != nil
	if now.Before(s.UpdatedAt) {
		for i := range next.Keys {
			for _, old := range s.Keys {
				if next.Keys[i].ID == old.ID && old.State == AddPending && next.Keys[i].State == Valid {
					next.Keys[i] = old
				}
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeBarrier(*m.state, next)
	revision, err = m.persist(ctx, next)
	if err != nil {
		m.pending = &next
		m.storageError = "RFC 5011 revocation persistence failed; managed validation is blocked"
		return err
	}
	next.Revision = revision
	m.state = managedCopy(next)
	m.pending = nil
	m.storageError = ""
	if next.ProbeInProgress {
		m.storageError = "unfinished RFC 5011 observation; waiting for an authenticated recovery probe"
	}
	return observationErr
}
