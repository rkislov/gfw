package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/netconfig"
)

type idsPending struct {
	IPSObserved *Snapshot  `json:"ips_observed,omitempty"`
	Previous    ids.Config `json:"previous"`
	Target      ids.Config `json:"target"`
}

type IDSRequest struct {
	ID             string     `json:"id"`
	Revision       int64      `json:"revision"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	Config         ids.Config `json:"config"`
}

type IDSState struct {
	FailurePolicy     string     `json:"failure_policy,omitempty"`
	IPSHooked         bool       `json:"ips_hooked"`
	IPSQueue          int        `json:"ips_queue,omitempty"`
	IPSError          string     `json:"ips_error,omitempty"`
	Enabled           bool       `json:"enabled"`
	ConfirmedRevision int64      `json:"confirmed_revision"`
	Confirmed         bool       `json:"confirmed_enabled"`
	Pending           *Record    `json:"pending,omitempty"`
	Runtime           ids.Status `json:"runtime"`
}

var idsChangeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

func (m *Manager) SetIDSBackend(b ids.Backend) { m.ids = b }

func (m *Manager) idsConfig() ids.Config {
	if m.j.IDSConfirmed != nil {
		return *m.j.IDSConfirmed
	}
	return ids.Empty()
}

func (m *Manager) IDSState() IDSState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := IDSState{Enabled: m.ids != nil, ConfirmedRevision: m.j.IDSRevision, Confirmed: m.idsConfig().Enabled}
	if p := m.j.Pending; p != nil {
		r := p.Record
		s.Pending = &r
	}
	if m.ids != nil {
		s.Runtime = m.ids.Status()
	}
	if p := m.j.Pending; p != nil && p.IDS != nil {
		m.ipsState(p.IDS.Target, p.IDS.IPSObserved, &s)
	} else {
		m.ipsState(m.idsConfig(), m.ipsConfirmed, &s)
	}
	return s
}

func (m *Manager) IDSPlan(c ids.Config) (ids.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ids == nil {
		return ids.Plan{}, errors.New("IDS backend disabled")
	}
	p, err := m.ids.Prepare(c)
	if err == nil {
		err = m.checkIPS(c, m.idsConfig())
	}
	p.CanApply = err == nil && p.Checked && m.j.Pending == nil && !m.stopping
	return p, err
}

func (m *Manager) IDSApply(req IDSRequest) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping || m.ids == nil {
		return Record{}, fmt.Errorf("%w: IDS backend disabled or agent stopping", ErrConflict)
	}
	if !idsChangeID.MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return Record{}, err
	}
	sum := sha256.Sum256(append([]byte("ids:"), raw...))
	digest := hex.EncodeToString(sum[:])
	if p := m.j.Pending; p != nil {
		if p.Record.ID == req.ID && p.Record.Digest == digest {
			return p.Record, nil
		}
		return Record{}, fmt.Errorf("%w: сначала завершите текущее изменение", ErrConflict)
	}
	for _, r := range m.j.History {
		if r.ID == req.ID {
			if r.Digest != digest {
				return Record{}, fmt.Errorf("%w: ID использован с другими параметрами", ErrConflict)
			}
			return r, nil
		}
	}
	if _, err = m.ids.Prepare(req.Config); err != nil {
		return Record{}, err
	}
	if err = m.checkIPS(req.Config, m.idsConfig()); err != nil {
		return Record{}, err
	}
	now := m.now()
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{
		Record: Record{Kind: "ids", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(),
			Deadline: m.expiresAt.UTC(), Digest: digest, Status: "applying"},
		IDS: &idsPending{Previous: m.idsConfig(), Target: req.Config},
	}
	if m.j.Version < 9 {
		m.j.Version = 9
	}
	if m.j.Version < 10 && (p.IDS.Previous.FileIOC != nil || p.IDS.Target.FileIOC != nil) {
		m.j.Version = 10
	}
	m.j.Pending = p
	if err = m.save(m.j); err != nil {
		m.j.Pending = nil
		return Record{}, err
	}
	if affectsFlow(p) {
		if err = m.pauseFlow(); err != nil {
			_, rb := m.rollback("suspending flowtable failed: " + err.Error())
			return Record{}, errors.Join(err, rb)
		}
	}
	if err = m.applyIDS(p.IDS); err != nil {
		_, rb := m.rollback("IDS apply failed: " + err.Error())
		return Record{}, errors.Join(err, rb)
	}
	p.Record.Status = "pending"
	if err = m.save(m.j); err != nil {
		_, rb := m.rollback("IDS persistence failed")
		return Record{}, errors.Join(err, rb)
	}
	if m.expired() {
		_, rb := m.rollback("IDS deadline expired during apply")
		return Record{}, errors.Join(ErrConflict, rb)
	}
	return p.Record, nil
}

func (m *Manager) checkIDSNetwork(c netconfig.Config) error {
	cfg := m.idsConfig()
	if !cfg.Enabled {
		return nil
	}
	old, next := m.networkConfig().Map(), c.Map()
	for _, name := range cfg.Interfaces {
		if _, managed := old[name]; managed {
			if link, kept := next[name]; !kept || !link.Up {
				return fmt.Errorf("интерфейс %s используется Suricata IDS; сначала измените настройки IDS", name)
			}
		}
	}
	return nil
}

func (m *Manager) restoreIDS(c ids.Config) error {
	if m.ids == nil {
		if c.Enabled {
			return errors.New("IDS backend disabled")
		}
		return nil
	}
	return m.ids.Activate(c)
}
