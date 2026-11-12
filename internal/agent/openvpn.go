package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/services"
	"net/netip"
	"regexp"
	"time"
)

type openvpnPending struct {
	Previous openvpn.RuntimeConfig `json:"previous"`
	Target   openvpn.RuntimeConfig `json:"target"`
}
type OpenVPNRequest struct {
	ID             string                `json:"id"`
	Revision       int64                 `json:"revision"`
	TimeoutSeconds int                   `json:"timeout_seconds"`
	Config         openvpn.RuntimeConfig `json:"config"`
}
type OpenVPNState struct {
	Active            openvpn.RuntimeConfig `json:"active"`
	RequiredCAs       []string              `json:"required_cas"`
	Enabled           bool                  `json:"enabled"`
	ConfirmedRevision int64                 `json:"confirmed_revision"`
	Confirmed         openvpn.RuntimeConfig `json:"confirmed"`
	Pending           *Record               `json:"pending,omitempty"`
	History           []Record              `json:"history"`
	Runtime           []openvpn.Status      `json:"runtime"`
	RuntimeError      string                `json:"runtime_error,omitempty"`
}

func (m *Manager) SetOpenVPNBackend(b openvpn.Backend) { m.openvpn = b }
func (m *Manager) openVPNConfig() openvpn.RuntimeConfig {
	if m.j.OpenVPNConfirmed != nil {
		return *m.j.OpenVPNConfirmed
	}
	return openvpn.RuntimeEmpty()
}
func (m *Manager) OpenVPNState() OpenVPNState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := OpenVPNState{Enabled: m.openvpn != nil, ConfirmedRevision: m.j.OpenVPNRevision, Confirmed: m.openVPNConfig(), History: append([]Record{}, m.j.History...)}
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	if m.openvpn != nil {
		active := m.openVPNConfig()
		if m.j.Pending != nil && m.j.Pending.OpenVPN != nil {
			active = m.j.Pending.OpenVPN.Target
		}
		s.Active = active
		all := active
		all.Instances = append(append([]openvpn.Instance{}, active.Instances...), m.openVPNConfig().Instances...)
		if m.j.Pending != nil && m.j.Pending.OpenVPN != nil {
			all.Instances = append(all.Instances, m.j.Pending.OpenVPN.Previous.Instances...)
		}
		s.RequiredCAs = m.openvpn.CAs(all)
		var err error
		s.Runtime, err = m.openvpn.Status(active)
		if err != nil {
			s.RuntimeError = err.Error()
		} else if err = m.openvpn.Verify(active); err != nil {
			s.RuntimeError = err.Error()
		}
	}
	return s
}
func (m *Manager) OpenVPNPlan(c openvpn.RuntimeConfig) (openvpn.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.openvpn == nil {
		return openvpn.Plan{}, errors.New("модуль OpenVPN в агенте отключён")
	}
	if err := m.openVPNSafety(c); err != nil {
		return openvpn.Plan{}, err
	}
	p, e := m.openvpn.Prepare(c, m.openVPNConfig())
	p.CanApply = e == nil && m.j.Pending == nil
	return p, e
}
func (m *Manager) OpenVPNApply(req OpenVPNRequest) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if m.openvpn == nil {
		return Record{}, errors.New("модуль OpenVPN в агенте отключён")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(append([]byte("openvpn:"), raw...))
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
	if err := m.openVPNSafety(req.Config); err != nil {
		return Record{}, err
	}
	if _, e := m.openvpn.Prepare(req.Config, m.openVPNConfig()); e != nil {
		return Record{}, e
	}
	previous := m.openVPNConfig()

	now := m.now()
	r := Record{Kind: "openvpn", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(), Deadline: now.Add(time.Duration(req.TimeoutSeconds) * time.Second).UTC(), Digest: digest, Status: "applying"}
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, OpenVPN: &openvpnPending{Previous: previous, Target: req.Config}}
	if m.j.Version < 6 {
		m.j.Version = 6
	}
	for _, v := range req.Config.Instances {
		if v.Auth != nil {
			m.j.Version = max(m.j.Version, 13)
			break
		}
	}
	m.j.Pending = p
	if e := m.save(m.j); e != nil {
		m.j.Pending = nil
		return Record{}, e
	}
	if e := m.openvpn.Activate(req.Config, previous); e != nil {
		_, rb := m.rollback("service apply failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	if e := m.restartConfirmedServices(); e != nil {
		_, rb := m.rollback("service rebind after OpenVPN failed")
		return Record{}, errors.Join(e, rb)
	}
	if e := m.openvpn.Verify(req.Config); e != nil {
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

func (m *Manager) openVPNActive() openvpn.RuntimeConfig {
	if m.j.Pending != nil && m.j.Pending.OpenVPN != nil {
		return m.j.Pending.OpenVPN.Target
	}
	return m.openVPNConfig()
}
func (m *Manager) OpenVPNStage(materials []openvpn.Material) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return ErrConflict
	}
	if m.openvpn == nil {
		return errors.New("OpenVPN отключён")
	}
	return m.openvpn.Stage(materials, m.openVPNActive())
}
func (m *Manager) OpenVPNRefresh(updates []openvpn.CRLUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return ErrConflict
	}
	if m.openvpn == nil {
		return errors.New("OpenVPN отключён")
	}
	return m.openvpn.Refresh(updates, m.openVPNActive())
}
func (m *Manager) OpenVPNLogs(id string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.openvpn == nil {
		return nil, errors.New("OpenVPN отключён")
	}
	return m.openvpn.Logs(id)
}
func (m *Manager) openVPNSafety(c openvpn.RuntimeConfig) error {
	for _, t := range m.ipsecConfig().Tunnels {
		for _, o := range c.Instances {
			if o.Interface == t.Interface {
				return errors.New("имя интерфейса занято IPsec")
			}
			if t.Enabled && o.Enabled && o.Mode == "server" && o.Protocol == "udp" && ikePort(o.Port) {
				return errors.New("UDP-порт занят IKE")
			}
		}
	}
	if e := openvpn.ValidateRuntime(c); e != nil {
		return e
	}
	if e := m.validateLAN(); e != nil {
		return e
	}
	active := openvpn.Active(c)
	old := openvpn.Active(m.openVPNConfig())
	for _, i := range c.Instances {
		if i.Interface == m.safety.LANInterface {
			return errors.New("OpenVPN не может менять LAN")
		}
		for _, n := range m.networkConfig().Interfaces {
			if n.Name == i.Interface {
				return errors.New("имя TUN занято модулем сети")
			}
		}
		for _, t := range m.wireGuardConfig().Tunnels {
			if t.Name == i.Interface {
				return errors.New("имя TUN занято WireGuard")
			}
			if i.Enabled && t.Enabled && i.Protocol == "udp" && t.ListenPort == i.Port && i.Mode == "server" {
				return errors.New("UDP-порт занят WireGuard")
			}
		}
		svc := m.servicesConfig()
		if i.Enabled && i.Mode == "server" && (i.Port == m.safety.ManagementPort || svc.DNS.Enabled && svc.DNS.Port == i.Port || i.Protocol == "udp" && svc.DHCP.Enabled && svc.DHCP.Port == i.Port) {
			return errors.New("порт VPN занят панелью или DNS/DHCP")
		}
	}
	if m.j.FirewallConfig != nil {
		for _, z := range m.j.FirewallConfig.Zones {
			for _, name := range z.Interfaces {
				if _, used := old[name]; used {
					if _, kept := active[name]; !kept {
						return errors.New("TUN используется подтверждённой зоной firewall")
					}
				}
			}
		}
	}
	for name, ips := range services.Interfaces(m.servicesConfig()) {
		if _, used := old[name]; used {
			next, kept := active[name]
			if !kept {
				return errors.New("TUN используется DNS/DHCP")
			}
			a, _ := netip.ParsePrefix(next.Address)
			for _, ip := range ips {
				if ip != a.Addr().String() {
					return errors.New("адрес TUN используется DNS/DHCP")
				}
			}
		}
	}
	return nil
}
func (m *Manager) restartConfirmedOpenVPN() error {
	if m.j.OpenVPNConfirmed == nil {
		return nil
	}
	if m.openvpn == nil {
		return errors.New("OpenVPN backend disabled")
	}
	return m.openvpn.Activate(*m.j.OpenVPNConfirmed, *m.j.OpenVPNConfirmed)
}

func (m *Manager) restartNetworkConsumers() error {
	if e := m.restartConfirmedOpenVPN(); e != nil {
		return e
	}
	if err := m.restartConfirmedServices(); err != nil {
		return err
	}
	if m.ids != nil && m.idsConfig().Enabled && m.ids.Verify(m.idsConfig()) != nil {
		_ = m.restoreIDS(m.idsConfig())
	}
	return nil
}

func (m *Manager) CloseOpenVPN(b interface{ Close() error }) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return b.Close()
}
