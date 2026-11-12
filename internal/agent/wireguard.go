package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/wireguard"
	"net/netip"
	"regexp"
	"time"
)

type wireguardPending struct {
	Previous wireguard.Config `json:"previous"`
	Target   wireguard.Config `json:"target"`
}
type WireGuardRequest struct {
	ID             string           `json:"id"`
	Revision       int64            `json:"revision"`
	TimeoutSeconds int              `json:"timeout_seconds"`
	Config         wireguard.Config `json:"config"`
}
type WireGuardState struct {
	Enabled           bool                     `json:"enabled"`
	ConfirmedRevision int64                    `json:"confirmed_revision"`
	Confirmed         wireguard.Config         `json:"confirmed"`
	Pending           *Record                  `json:"pending,omitempty"`
	History           []Record                 `json:"history"`
	Runtime           []wireguard.TunnelStatus `json:"runtime"`
	RuntimeError      string                   `json:"runtime_error,omitempty"`
}

func (m *Manager) SetWireGuardBackend(b wireguard.Backend) { m.wireguard = b }
func (m *Manager) wireGuardConfig() wireguard.Config {
	if m.j.WireGuardConfirmed != nil {
		return *m.j.WireGuardConfirmed
	}
	return wireguard.Empty()
}
func (m *Manager) WireGuardState() WireGuardState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := WireGuardState{Enabled: m.wireguard != nil, ConfirmedRevision: m.j.WireGuardRevision, Confirmed: m.wireGuardConfig(), History: append([]Record{}, m.j.History...)}
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	if m.wireguard != nil {
		active := m.wireGuardConfig()
		if m.j.Pending != nil && m.j.Pending.WireGuard != nil {
			active = m.j.Pending.WireGuard.Target
		}
		var err error
		s.Runtime, err = m.wireguard.Status(active)
		if err != nil {
			s.RuntimeError = err.Error()
		}
	}
	return s
}
func (m *Manager) WireGuardPlan(c wireguard.Config) (wireguard.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wireguard == nil {
		return wireguard.Plan{}, errors.New("модуль WireGuard в агенте отключён")
	}
	if err := m.wireGuardSafety(c); err != nil {
		return wireguard.Plan{}, err
	}
	p, e := m.wireguard.Prepare(c, m.wireGuardConfig())
	p.CanApply = e == nil && m.j.Pending == nil
	return p, e
}
func (m *Manager) WireGuardApply(req WireGuardRequest) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if m.wireguard == nil {
		return Record{}, errors.New("модуль WireGuard в агенте отключён")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(append([]byte("wireguard:"), raw...))
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
		return Record{}, fmt.Errorf("%w: сначала завершите текущее изменение", ErrConflict)
	}
	if err := m.wireGuardSafety(req.Config); err != nil {
		return Record{}, err
	}
	if _, e := m.wireguard.Prepare(req.Config, m.wireGuardConfig()); e != nil {
		return Record{}, e
	}
	previous := m.wireGuardConfig()

	now := m.now()
	r := Record{Kind: "wireguard", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(), Deadline: now.Add(time.Duration(req.TimeoutSeconds) * time.Second).UTC(), Digest: digest, Status: "applying"}
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, WireGuard: &wireguardPending{Previous: previous, Target: req.Config}}
	if m.j.Version < 5 {
		m.j.Version = 5
	}
	m.j.Pending = p
	if e := m.save(m.j); e != nil {
		m.j.Pending = nil
		return Record{}, e
	}
	if e := m.wireguard.Activate(req.Config, previous); e != nil {
		_, rb := m.rollback("service apply failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	if e := m.restartConfirmedServices(); e != nil {
		_, rb := m.rollback("service rebind after WireGuard failed")
		return Record{}, errors.Join(e, rb)
	}
	if e := m.wireguard.Verify(req.Config); e != nil {
		_, rb := m.rollback("service readiness failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	p.Record.Status = "pending"
	if e := m.save(m.j); e != nil {
		_, rb := m.rollback("service persistence failed")
		return Record{}, errors.Join(e, rb)
	}
	if m.expired() {
		_, e := m.rollback("service deadline expired during apply")
		return Record{}, errors.Join(ErrConflict, e)
	}
	return p.Record, nil
}

func (m *Manager) wireGuardSafety(c wireguard.Config) error {
	for _, t := range m.ipsecConfig().Tunnels {
		for _, w := range c.Tunnels {
			if w.Name == t.Interface {
				return errors.New("имя интерфейса занято IPsec")
			}
			if t.Enabled && w.Enabled && ikePort(w.ListenPort) {
				return errors.New("UDP-порт занят IKE")
			}
		}
	}
	for _, i := range m.openVPNConfig().Instances {
		for _, t := range c.Tunnels {
			if t.Name == i.Interface {
				return errors.New("имя интерфейса занято OpenVPN")
			}
			if i.Enabled && i.Mode == "server" && i.Protocol == "udp" && t.Enabled && t.ListenPort == i.Port {
				return errors.New("UDP-порт занят OpenVPN")
			}
		}
	}

	active := wireguard.Active(c)
	for name := range active {
		if name == m.safety.LANInterface {
			return errors.New("нельзя изменить защищённый LAN через WireGuard")
		}
	}
	if m.j.NetworkConfirmed != nil {
		for _, l := range m.j.NetworkConfirmed.Interfaces {
			for _, t := range c.Tunnels {
				if t.Name == l.Name {
					return errors.New("интерфейс уже управляется модулем сети")
				}
			}
		}
	}
	if m.j.FirewallConfig != nil {
		for _, z := range m.j.FirewallConfig.Zones {
			for _, name := range z.Interfaces {
				if _, old := wireguard.Active(m.wireGuardConfig())[name]; old {
					if _, kept := active[name]; !kept {
						return fmt.Errorf("туннель %s используется подтверждённой зоной %s", name, z.Name)
					}
				}
			}
		}
	}
	for name, ips := range services.Interfaces(m.servicesConfig()) {
		if _, old := wireguard.Active(m.wireGuardConfig())[name]; old {
			next, kept := active[name]
			if !kept {
				return errors.New("туннель используется DNS/DHCP")
			}
			for _, ip := range ips {
				a, _ := netip.ParseAddr(ip)
				found := false
				for _, s := range next.Addresses {
					n, _ := netip.ParsePrefix(s)
					if n.Addr() == a {
						found = true
					}
				}
				if !found {
					return errors.New("адрес туннеля используется DNS/DHCP")
				}
			}
		}
	}
	svc := m.servicesConfig()
	for _, t := range active {
		if svc.DNS.Enabled && svc.DNS.Port == t.ListenPort || svc.DHCP.Enabled && svc.DHCP.Port == t.ListenPort {
			return errors.New("UDP-порт WireGuard занят DNS/DHCP")
		}
	}
	return nil
}
func (m *Manager) WireGuardKey(kind string) (wireguard.KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wireguard == nil {
		return wireguard.KeyInfo{}, errors.New("WireGuard отключён")
	}
	return m.wireguard.GenerateKey(kind)
}
func (m *Manager) WireGuardExport(ctx context.Context, t, p string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wireguard == nil {
		return "", errors.New("WireGuard отключён")
	}
	return m.wireguard.Export(m.wireGuardConfig(), t, p)
}
