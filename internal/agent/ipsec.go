package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/vpncred"
	"net/netip"
	"regexp"
	"time"
)

type ipsecPending struct {
	Previous ipsec.Config `json:"previous"`
	Target   ipsec.Config `json:"target"`
}
type IPsecRequest struct {
	ID             string       `json:"id"`
	Revision       int64        `json:"revision"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	Config         ipsec.Config `json:"config"`
}
type IPsecState struct {
	Active            ipsec.Config   `json:"active"`
	RequiredCAs       []string       `json:"required_cas"`
	Enabled           bool           `json:"enabled"`
	ConfirmedRevision int64          `json:"confirmed_revision"`
	Confirmed         ipsec.Config   `json:"confirmed"`
	Pending           *Record        `json:"pending,omitempty"`
	History           []Record       `json:"history"`
	Runtime           []ipsec.Status `json:"runtime"`
	RuntimeError      string         `json:"runtime_error,omitempty"`
}

func (m *Manager) SetIPsecBackend(b ipsec.Backend) { m.ipsec = b }
func (m *Manager) ipsecConfig() ipsec.Config {
	if m.j.IPsecConfirmed != nil {
		return *m.j.IPsecConfirmed
	}
	return ipsec.Empty()
}
func (m *Manager) IPsecState() IPsecState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := IPsecState{Enabled: m.ipsec != nil, ConfirmedRevision: m.j.IPsecRevision, Confirmed: m.ipsecConfig(), History: append([]Record{}, m.j.History...)}
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	if m.ipsec != nil {
		active := m.ipsecConfig()
		if m.j.Pending != nil && m.j.Pending.IPsec != nil {
			active = m.j.Pending.IPsec.Target
		}
		s.Active = active
		all := active
		all.Tunnels = append(append([]ipsec.Tunnel{}, active.Tunnels...), m.ipsecConfig().Tunnels...)
		if m.j.Pending != nil && m.j.Pending.IPsec != nil {
			all.Tunnels = append(all.Tunnels, m.j.Pending.IPsec.Previous.Tunnels...)
		}
		s.RequiredCAs = m.ipsec.CAs(all)
		var err error
		s.Runtime, err = m.ipsec.Status(active)
		if err != nil {
			s.RuntimeError = err.Error()
		} else if err = m.ipsec.Verify(active); err != nil {
			s.RuntimeError = err.Error()
		}
	}
	return s
}
func (m *Manager) IPsecPlan(c ipsec.Config) (ipsec.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ipsec == nil {
		return ipsec.Plan{}, errors.New("модуль IPsec в агенте отключён")
	}
	if err := m.ipsecSafety(c); err != nil {
		return ipsec.Plan{}, err
	}
	p, e := m.ipsec.Prepare(c, m.ipsecConfig())
	p.CanApply = e == nil && m.j.Pending == nil
	return p, e
}
func (m *Manager) IPsecApply(req IPsecRequest) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if m.ipsec == nil {
		return Record{}, errors.New("модуль IPsec в агенте отключён")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(append([]byte("ipsec:"), raw...))
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
	if err := m.ipsecSafety(req.Config); err != nil {
		return Record{}, err
	}
	if _, e := m.ipsec.Prepare(req.Config, m.ipsecConfig()); e != nil {
		return Record{}, e
	}
	previous := m.ipsecConfig()

	now := m.now()
	r := Record{Kind: "ipsec", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(), Deadline: now.Add(time.Duration(req.TimeoutSeconds) * time.Second).UTC(), Digest: digest, Status: "applying"}
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, IPsec: &ipsecPending{Previous: previous, Target: req.Config}}
	if m.j.Version < 7 {
		m.j.Version = 7
	}
	for _, v := range req.Config.Tunnels {
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
	if e := m.pauseFlow(); e != nil {
		_, rb := m.rollback("suspending flowtable failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	if e := m.ipsec.Activate(req.Config, previous); e != nil {
		_, rb := m.rollback("service apply failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	if e := m.ipsec.Verify(req.Config); e != nil {
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

func (m *Manager) ipsecActive() ipsec.Config {
	if m.j.Pending != nil && m.j.Pending.IPsec != nil {
		return m.j.Pending.IPsec.Target
	}
	return m.ipsecConfig()
}
func (m *Manager) IPsecStage(materials []ipsec.Material) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return ErrConflict
	}
	if m.ipsec == nil {
		return errors.New("IPsec отключён")
	}
	return m.ipsec.Stage(materials, m.ipsecActive())
}
func (m *Manager) IPsecRefresh(updates []vpncred.CRLUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return ErrConflict
	}
	if m.ipsec == nil {
		return errors.New("IPsec отключён")
	}
	return m.ipsec.Refresh(updates, m.ipsecActive())
}
func (m *Manager) IPsecLogs() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ipsec == nil {
		return nil, errors.New("IPsec отключён")
	}
	return m.ipsec.Logs()
}
func (m *Manager) ipsecSafety(c ipsec.Config) error {
	if e := ipsec.Validate(c); e != nil {
		return e
	}
	if e := m.validateLAN(); e != nil {
		return e
	}
	active := ipsec.Active(c)
	for _, t := range c.Tunnels {
		if t.Interface == m.safety.LANInterface {
			return errors.New("IPsec не может менять LAN")
		}
		for _, n := range m.networkConfig().Interfaces {
			if n.Name == t.Interface {
				return errors.New("имя XFRM занято модулем сети")
			}
		}
		for _, w := range m.wireGuardConfig().Tunnels {
			if w.Name == t.Interface {
				return errors.New("имя XFRM занято WireGuard")
			}
		}
		for _, o := range m.openVPNConfig().Instances {
			if o.Interface == t.Interface {
				return errors.New("имя XFRM занято OpenVPN")
			}
		}
	}
	if len(active) > 0 {
		for _, w := range m.wireGuardConfig().Tunnels {
			if w.Enabled && ikePort(w.ListenPort) {
				return errors.New("UDP-порт IKE занят WireGuard")
			}
		}
		for _, o := range m.openVPNConfig().Instances {
			if o.Enabled && o.Mode == "server" && o.Protocol == "udp" && ikePort(o.Port) {
				return errors.New("UDP-порт IKE занят OpenVPN")
			}
		}
		svc := m.servicesConfig()
		if svc.DNS.Enabled && ikePort(svc.DNS.Port) || svc.DHCP.Enabled && ikePort(svc.DHCP.Port) {
			return errors.New("UDP-порт IKE занят DNS/DHCP")
		}
	}
	if m.j.FirewallConfig != nil {
		old := ipsec.Active(m.ipsecConfig())
		for _, z := range m.j.FirewallConfig.Zones {
			for _, name := range z.Interfaces {
				if _, used := old[name]; used {
					if _, kept := active[name]; !kept {
						return errors.New("XFRM используется подтверждённой зоной firewall")
					}
				}
			}
		}
	}
	return nil
}
func ikePort(port int) bool { return port == 500 || port == 4500 }
func (m *Manager) CloseIPsec() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ipsec == nil {
		return nil
	}
	return m.ipsec.Close()
}

func (m *Manager) checkIPsecNetwork(c netconfig.Config) error {
	for _, t := range m.ipsecConfig().Tunnels {
		for _, n := range c.Interfaces {
			if n.Name == t.Interface {
				return errors.New("XFRM изменяется через IPsec")
			}
			if n.Parent == t.Interface {
				return errors.New("XFRM не может быть родительским интерфейсом etcnet")
			}
			for _, member := range n.Members {
				if member == t.Interface {
					return errors.New("XFRM нельзя включить в bridge или bond")
				}
			}
		}
		if !t.Enabled {
			continue
		}
		addresses := map[netip.Addr]bool{}
		for _, n := range c.Interfaces {
			for _, s := range n.Addresses {
				p, e := netip.ParsePrefix(s)
				if e != nil {
					continue
				}
				if n.Up {
					addresses[p.Addr()] = true
				}
				for _, r := range t.RemoteNetworks {
					if p.Overlaps(netip.MustParsePrefix(r)) {
						return errors.New("локальная сеть пересекается с подтверждённым IPsec")
					}
				}
			}
		}
		local := netip.MustParseAddr(t.LocalAddress)
		for _, n := range m.networkConfig().Interfaces {
			for _, s := range n.Addresses {
				if p, e := netip.ParsePrefix(s); e == nil && p.Addr() == local && !addresses[local] {
					return errors.New("локальный адрес используется подтверждённым IPsec")
				}
			}
		}
		for _, route := range c.Routes {
			if route.Interface == t.Interface {
				return errors.New("маршрут XFRM управляется модулем IPsec")
			}
			if p, e := netip.ParsePrefix(route.Destination); e == nil && p.Bits() > 0 {
				for _, r := range t.RemoteNetworks {
					if p.Overlaps(netip.MustParsePrefix(r)) {
						return errors.New("маршрут пересекается с подтверждённым IPsec")
					}
				}
			}
		}
	}
	return nil
}
