package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/xdpguard"
)

type xdpPending struct {
	Previous xdpguard.Config `json:"previous"`
	Target   xdpguard.Config `json:"target"`
}

type XDPRequest struct {
	ID             string          `json:"id"`
	Revision       int64           `json:"revision"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	Config         xdpguard.Config `json:"config"`
}

type XDPState struct {
	Enabled   bool              `json:"enabled"`
	Revision  int64             `json:"revision"`
	Confirmed xdpguard.Profile  `json:"confirmed"`
	Target    *xdpguard.Profile `json:"target,omitempty"`
	WAN       []string          `json:"wan"`
	Runtime   []xdpguard.Port   `json:"runtime"`
	Pending   *Record           `json:"pending,omitempty"`
	History   []Record          `json:"history"`
	Error     string            `json:"error,omitempty"`
}

var xdpChangeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

func (m *Manager) SetXDPBackend(b xdpguard.Backend) { m.xdp = b }

func (m *Manager) xdpConfig() xdpguard.Config {
	if m.j.XDPConfirmed != nil {
		return *m.j.XDPConfirmed
	}
	return xdpguard.Config{}
}

func wanInterfaces(c *policy.Config, lan string) []string {
	names := []string{}
	if c != nil {
		for _, zone := range c.Zones {
			if zone.Kind == "wan" {
				for _, name := range zone.Interfaces {
					if name != lan {
						names = append(names, name)
					}
				}
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func (m *Manager) checkXDPZones(config xdpguard.Config, firewall *policy.Config) error {
	names := wanInterfaces(firewall, m.safety.LANInterface)
	for _, name := range config.Interfaces {
		if !slices.Contains(names, name) {
			return fmt.Errorf("%s должен входить в подтверждённую зону WAN и отличаться от интерфейса управления LAN", name)
		}
	}
	return nil
}

func (m *Manager) XDPState() XDPState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := XDPState{Enabled: m.xdp != nil, Revision: m.j.XDPRevision, Confirmed: m.xdpConfig().Profile(), WAN: wanInterfaces(m.j.FirewallConfig, m.safety.LANInterface),
		Runtime: []xdpguard.Port{}, History: []Record{}, Error: m.xdpError}
	if p := m.j.Pending; p != nil {
		r := p.Record
		s.Pending = &r
		if p.XDP != nil {
			target := p.XDP.Target.Profile()
			s.Target = &target
		}
	}
	for _, r := range m.j.History {
		if r.Kind == "xdp" {
			s.History = append(s.History, r)
		}
	}
	if m.xdp != nil {
		ports, err := m.xdp.Ports()
		if err != nil {
			s.Error = err.Error()
		} else {
			s.Runtime = ports
		}
		slices.SortFunc(s.Runtime, func(a, b xdpguard.Port) int { return strings.Compare(a.Name, b.Name) })
	}
	return s
}

func (m *Manager) XDPApply(req XDPRequest) (Record, error) {
	cfg, err := req.Config.Normalize()
	if err != nil {
		return Record{}, err
	}
	req.Config = cfg
	if !xdpChangeID.MatchString(req.ID) || req.Revision < 0 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, текущая ревизия и срок 30–600 секунд")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return Record{}, err
	}
	sum := sha256.Sum256(append([]byte("xdp:"), raw...))
	digest := hex.EncodeToString(sum[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.xdp == nil || m.stopping {
		return Record{}, errors.New("ранняя фильтрация XDP недоступна")
	}
	if p := m.j.Pending; p != nil {
		if p.Record.ID == req.ID && p.Record.Digest == digest {
			return p.Record, nil
		}
		return Record{}, fmt.Errorf("%w: сначала завершите текущее изменение", ErrConflict)
	}
	for _, r := range m.j.History {
		if r.ID != req.ID {
			continue
		}
		if r.Digest == digest {
			return r, nil
		}
		return Record{}, fmt.Errorf("%w: ID использован с другими параметрами", ErrConflict)
	}
	if req.Revision != m.j.XDPRevision {
		return Record{}, fmt.Errorf("%w: ревизия профиля XDP изменилась", ErrConflict)
	}
	if err = m.checkXDPZones(cfg, m.j.FirewallConfig); err != nil {
		return Record{}, err
	}
	if len(cfg.Interfaces) > 0 {
		if m.j.Confirmed == nil {
			return Record{}, errors.New("сначала подтвердите базовую политику межсетевого экрана")
		}
		if err = m.validateLAN(); err != nil {
			return Record{}, err
		}
		actual, e := m.backend.Snapshot()
		if e != nil {
			return Record{}, e
		}
		if !actual.Exists {
			return Record{}, errors.New("действующая таблица firewall отсутствует")
		}
	}
	if err = m.xdp.Check(cfg, m.safety.LANInterface); err != nil {
		return Record{}, err
	}
	now := m.now()
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: Record{Kind: "xdp", ID: req.ID, Revision: req.Revision + 1, CreatedAt: now.UTC(), Deadline: m.expiresAt.UTC(), Digest: digest, Status: "applying"},
		XDP: &xdpPending{Previous: m.xdpConfig(), Target: cfg}}
	m.j.Version = max(m.j.Version, 11)
	m.j.Pending = p
	if err = m.save(m.j); err != nil {
		m.j.Pending = nil
		return Record{}, err
	}
	if err = m.pauseFlow(); err != nil {
		_, rb := m.rollback("suspending flowtable failed: " + err.Error())
		return Record{}, errors.Join(err, rb)
	}
	if err = m.xdp.Activate(cfg, m.safety.LANInterface); err != nil {
		_, rb := m.rollback("XDP apply failed: " + err.Error())
		return Record{}, errors.Join(err, rb)
	}
	m.xdpError = ""
	m.xdpRetry = time.Time{}
	p.Record.Status = "pending"
	if err = m.save(m.j); err != nil {
		_, rb := m.rollback("XDP persistence failed")
		return Record{}, errors.Join(err, rb)
	}
	if m.expired() {
		_, rb := m.rollback("XDP deadline expired during apply")
		return Record{}, errors.Join(ErrConflict, rb)
	}
	return p.Record, nil
}

func (m *Manager) verifyXDP(c xdpguard.Config) error {
	if m.xdp == nil {
		return errors.New("ранняя фильтрация XDP отключена")
	}
	if err := m.checkXDPZones(c, m.j.FirewallConfig); err != nil {
		return err
	}
	return m.xdp.Verify(c, m.safety.LANInterface)
}

// Restore always removes a failed staged profile. If the confirmed WAN has
// disappeared, nftables stays active and Tick retries restoration when safe.
func (m *Manager) restoreXDP(c xdpguard.Config) error {
	if m.xdp == nil {
		return nil
	} // The previous process owned unpinned BPF links.
	err := m.checkXDPZones(c, m.j.FirewallConfig)
	if err == nil {
		err = m.xdp.Activate(c, m.safety.LANInterface)
	}
	if err == nil {
		m.xdpError = ""
		m.xdpRetry = time.Time{}
		return nil
	}
	m.xdpError = "Не удалось восстановить профиль XDP: " + err.Error()
	m.xdpRetry = m.now().Add(5 * time.Second)
	return m.xdp.Deactivate()
}

func (m *Manager) maintainXDP() error {
	if m.xdp == nil {
		return nil
	}
	p := m.j.Pending
	if p != nil && p.Network != nil {
		return nil
	}
	if p != nil && p.XDP != nil {
		if err := m.verifyXDP(p.XDP.Target); err != nil {
			_, rb := m.rollback("XDP safety check failed: " + err.Error())
			return rb
		}
		return nil
	}
	cfg := m.xdpConfig()
	if len(cfg.Interfaces) == 0 {
		return nil
	}
	if err := m.verifyXDP(cfg); err == nil {
		return nil
	}
	if !m.xdpRetry.IsZero() && m.now().Before(m.xdpRetry) {
		return nil
	}
	if err := m.xdp.Deactivate(); err != nil {
		return err
	}
	return m.restoreXDP(cfg)
}
