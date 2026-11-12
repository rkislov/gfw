package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/rkislov/gfw/internal/netconfig"
)

type networkPending struct {
	Previous netconfig.Snapshot `json:"previous"`
	Target   netconfig.Config   `json:"target"`
}
type NetworkRequest struct {
	ID             string           `json:"id"`
	Revision       int64            `json:"revision"`
	TimeoutSeconds int              `json:"timeout_seconds"`
	Config         netconfig.Config `json:"config"`
}
type NetworkState struct {
	Backend           string           `json:"backend,omitempty"`
	Enabled           bool             `json:"enabled"`
	ConfirmedRevision int64            `json:"confirmed_revision"`
	Confirmed         netconfig.Config `json:"confirmed"`
	Pending           *Record          `json:"pending,omitempty"`
	History           []Record         `json:"history"`
	LAN               string           `json:"lan_interface"`
}

// SetNetworkBackend is called during startup, before Recover or HTTP serving.
func (m *Manager) SetNetworkBackend(b netconfig.Backend) { m.network = b }
func (m *Manager) networkConfig() netconfig.Config {
	if m.j.NetworkConfirmed != nil {
		return *m.j.NetworkConfirmed
	}
	return netconfig.Empty()
}
func (m *Manager) networkMode() string {
	if backend, ok := m.network.(interface{ BackendName() string }); ok {
		return backend.BackendName()
	}
	if m.network != nil {
		return "etcnet"
	}
	return ""
}

func (m *Manager) NetworkState() NetworkState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := NetworkState{Backend: m.networkMode(), Enabled: m.network != nil, ConfirmedRevision: m.j.NetworkRevision, Confirmed: m.networkConfig(), History: append([]Record{}, m.j.History...), LAN: m.safety.LANInterface}
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	return s
}
func (m *Manager) NetworkPlan(c netconfig.Config) (netconfig.Plan, error) {
	c = netconfig.Canonical(c)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.network == nil {
		return netconfig.Plan{}, errors.New("управление сетью в агенте отключено")
	}
	if err := m.checkZoneDependencies(c); err != nil {
		return netconfig.Plan{}, err
	}
	_, plan, err := m.network.Prepare(c, m.networkConfig())
	if m.j.ServicesConfirmed != nil {
		plan.Warnings = append(plan.Warnings, "После изменения интерфейсов слушатели DNS/DHCP будут привязаны заново; возможна краткая пауза.")
	}
	plan.CanApply = err == nil && m.j.Pending == nil
	return plan, err
}
func (m *Manager) NetworkApply(req NetworkRequest) (Record, error) {
	req.Config = netconfig.Canonical(req.Config)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if m.network == nil {
		return Record{}, errors.New("управление сетью в агенте отключено")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(append([]byte("network:"), raw...))
	digest := hex.EncodeToString(sum[:])
	if p := m.j.Pending; p != nil && p.Record.ID == req.ID {
		if p.Record.Digest != digest {
			return Record{}, fmt.Errorf("%w: ID использован с другими параметрами", ErrConflict)
		}
		return p.Record, nil
	}
	for _, r := range m.j.History {
		if r.ID == req.ID {
			if r.Digest != digest {
				return Record{}, fmt.Errorf("%w: ID использован с другими параметрами", ErrConflict)
			}
			return r, nil
		}
	}
	if m.j.Pending != nil {
		return Record{}, fmt.Errorf("%w: сначала завершите текущее изменение сети или firewall", ErrConflict)
	}
	previous, _, err := m.network.Prepare(req.Config, m.networkConfig())
	if err := m.checkZoneDependencies(req.Config); err != nil {
		return Record{}, err
	}
	if err != nil {
		return Record{}, err
	}
	now := m.now()
	r := Record{Kind: "network", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(), Deadline: now.Add(time.Duration(req.TimeoutSeconds) * time.Second).UTC(), Digest: digest, Status: "applying"}
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, Network: &networkPending{Previous: previous, Target: req.Config}}
	// Older agents must refuse the journal instead of silently discarding the
	// network recovery fields on a downgrade.
	m.j.Version = max(m.j.Version, 2)
	if previous.Netplan != nil {
		m.j.Version = max(m.j.Version, 14)
	}
	m.j.Pending = p
	if err = m.save(m.j); err != nil {
		m.j.Pending = nil
		return Record{}, err
	}
	// Snapshot and intent have reached stable storage before either etcnet or
	// kernel state changes. Rollback remains independent of the web connection.
	if affectsFlow(p) {
		if err = m.pauseFlow(); err != nil {
			_, rb := m.rollback("suspending flowtable failed: " + err.Error())
			return Record{}, errors.Join(err, rb)
		}
	}
	if m.xdp != nil && len(m.xdpConfig().Interfaces) > 0 {
		if err = m.xdp.Deactivate(); err != nil {
			_, rb := m.rollback("suspending XDP failed: " + err.Error())
			return Record{}, errors.Join(err, rb)
		}
		m.xdpError = "Ранняя фильтрация приостановлена до подтверждения сетевых изменений"
	}
	if err = m.network.Activate(req.Config, m.networkConfig()); err != nil {
		_, rb := m.rollback("network apply failed: " + err.Error())
		return Record{}, errors.Join(err, rb)
	}
	if err = m.restartNetworkConsumers(); err != nil {
		_, rb := m.rollback("service rebind after network change failed: " + err.Error())
		return Record{}, errors.Join(err, rb)
	}
	p.Record.Status = "pending"
	if err = m.save(m.j); err != nil {
		_, rb := m.rollback("network state persistence failed")
		return Record{}, errors.Join(err, rb)
	}
	if m.expired() {
		_, err = m.rollback("network deadline expired during apply")
		return Record{}, errors.Join(ErrConflict, err)
	}
	return p.Record, nil
}

func (m *Manager) checkZoneDependencies(c netconfig.Config) error {
	if err := m.checkIDSNetwork(c); err != nil {
		return err
	}
	if err := m.checkIPsecNetwork(c); err != nil {
		return err
	}

	for _, i := range m.openVPNConfig().Instances {
		for _, n := range c.Interfaces {
			if n.Name == i.Interface {
				return errors.New("TUN изменяется только через OpenVPN")
			}
		}
		if i.Enabled && i.Mode == "server" {
			for _, before := range m.networkConfig().Interfaces {
				for _, s := range before.Addresses {
					a, _ := netip.ParsePrefix(s)
					if a.Addr().String() == i.BindAddress {
						kept := false
						for _, after := range c.Interfaces {
							if after.Name == before.Name && after.Up {
								for _, s := range after.Addresses {
									a, _ := netip.ParsePrefix(s)
									if a.Addr().String() == i.BindAddress {
										kept = true
									}
								}
							}
						}
						if !kept {
							return errors.New("адрес интерфейса используется OpenVPN bind")
						}
					}
				}
			}
		}
	}

	for _, t := range m.wireGuardConfig().Tunnels {
		for _, l := range c.Interfaces {
			if l.Name == t.Name {
				return errors.New("WireGuard-интерфейс изменяется только через модуль VPN")
			}
		}
	}
	if err := m.checkServiceDependencies(c); err != nil {
		return err
	}
	if m.j.FirewallConfig == nil {
		return nil
	}
	old := m.networkConfig().Map()
	next := c.Map()
	for _, z := range m.j.FirewallConfig.Zones {
		for _, name := range z.Interfaces {
			if _, managed := old[name]; managed {
				if _, kept := next[name]; !kept {
					return fmt.Errorf("интерфейс %s используется подтверждённой зоной %s; сначала измените политику firewall", name, z.Name)
				}
			}
		}
	}
	return nil
}
