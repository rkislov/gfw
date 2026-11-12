package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/services"
	"net/netip"
	"regexp"
	"time"
)

type servicesPending struct {
	Previous services.Config `json:"previous"`
	Target   services.Config `json:"target"`
}
type ServicesRequest struct {
	ID             string          `json:"id"`
	Revision       int64           `json:"revision"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	Config         services.Config `json:"config"`
}
type ServicesState struct {
	SecurityFeed      *feed.FilterSummary `json:"security_feed,omitempty"`
	Enabled           bool                `json:"enabled"`
	ConfirmedRevision int64               `json:"confirmed_revision"`
	Confirmed         services.Config     `json:"confirmed"`
	Pending           *Record             `json:"pending,omitempty"`
	History           []Record            `json:"history"`
	Runtime           services.Status     `json:"runtime"`
}

func (m *Manager) SetServicesBackend(b services.Backend) { m.services = b }
func (m *Manager) servicesConfig() services.Config {
	if m.j.ServicesConfirmed != nil {
		return *m.j.ServicesConfirmed
	}
	return services.Default()
}
func (m *Manager) ServicesState() ServicesState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := ServicesState{Enabled: m.services != nil, ConfirmedRevision: m.j.ServicesRevision, Confirmed: m.servicesConfig(), History: append([]Record{}, m.j.History...)}
	s.SecurityFeed = s.Confirmed.DNS.SecurityFeed.Summary()
	s.Confirmed.DNS.SecurityFeed = nil
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	if m.services != nil {
		s.Runtime = m.services.Status()
	}
	return s
}
func (m *Manager) ServicesPlan(c services.Config) (services.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.services == nil {
		return services.Plan{}, errors.New("модули DNS/DHCP в агенте отключены")
	}
	if err := m.serviceSafety(c); err != nil {
		return services.Plan{}, err
	}
	p, e := m.services.Prepare(c)
	p.CanApply = e == nil && m.j.Pending == nil
	return p, e
}
func (m *Manager) ServicesApply(req ServicesRequest) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if m.services == nil {
		return Record{}, errors.New("модули DNS/DHCP в агенте отключены")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("нужны ID, ревизия и срок 30–600 секунд")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(append([]byte("services:"), raw...))
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
	if err := m.serviceSafety(req.Config); err != nil {
		return Record{}, err
	}
	if _, e := m.services.Prepare(req.Config); e != nil {
		return Record{}, e
	}
	previous := m.servicesConfig()
	if _, e := m.services.Prepare(previous); e != nil {
		return Record{}, fmt.Errorf("нельзя подготовить откат сервисов: %w", e)
	}
	now := m.now()
	r := Record{Kind: "services", ID: req.ID, Revision: req.Revision, CreatedAt: now.UTC(), Deadline: now.Add(time.Duration(req.TimeoutSeconds) * time.Second).UTC(), Digest: digest, Status: "applying"}
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, Services: &servicesPending{Previous: previous, Target: req.Config}}
	if m.j.Version < 4 {
		m.j.Version = 4
	}
	m.j.Pending = p
	if e := m.save(m.j); e != nil {
		m.j.Pending = nil
		return Record{}, e
	}
	if e := m.services.Activate(req.Config); e != nil {
		_, rb := m.rollback("service apply failed: " + e.Error())
		return Record{}, errors.Join(e, rb)
	}
	if e := m.services.Verify(req.Config); e != nil {
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

func (m *Manager) serviceSafety(c services.Config) error {
	for _, t := range m.ipsecConfig().Tunnels {
		if t.Enabled && (c.DNS.Enabled && ikePort(c.DNS.Port) || c.DHCP.Enabled && ikePort(c.DHCP.Port)) {
			return errors.New("UDP-порт занят IKE")
		}
	}
	for _, i := range m.openVPNConfig().Instances {
		if i.Enabled && i.Mode == "server" && (c.DNS.Enabled && c.DNS.Port == i.Port || i.Protocol == "udp" && c.DHCP.Enabled && c.DHCP.Port == i.Port) {
			return errors.New("порт занят OpenVPN")
		}
	}

	for _, t := range m.wireGuardConfig().Tunnels {
		if t.Enabled && (c.DNS.Enabled && c.DNS.Port == t.ListenPort || c.DHCP.Enabled && c.DHCP.Port == t.ListenPort) {
			return errors.New("UDP-порт DNS/DHCP занят WireGuard")
		}
	}
	if c.DNS.Enabled && c.DNS.Port == m.safety.ManagementPort {
		return errors.New("DNS не может занимать TCP-порт панели управления")
	}
	return nil
}
func (m *Manager) ServiceLeases(ctx context.Context) ([]services.Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.services.(interface {
		Leases(context.Context) ([]services.Lease, error)
	})
	if !ok {
		return []services.Lease{}, nil
	}
	return b.Leases(ctx)
}
func (m *Manager) ServiceDNSLogs() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.services.(interface{ DNSLogs() any }); ok {
		return b.DNSLogs()
	}
	return []any{}
}
func (m *Manager) checkServiceDependencies(c netconfig.Config) error {
	old, next := m.networkConfig().Map(), c.Map()
	for name, ips := range services.Interfaces(m.servicesConfig()) {
		_, managed := old[name]
		target, ok := next[name]
		if !managed && !ok {
			continue
		}
		if !ok || !target.Up {
			return fmt.Errorf("интерфейс %s используется подтверждёнными DNS/DHCP; сначала измените сервисы", name)
		}
		for _, ip := range ips {
			found := false
			for _, s := range target.Addresses {
				prefix, err := netip.ParsePrefix(s)
				address, _ := netip.ParseAddr(ip)
				if err == nil && prefix.Addr() == address {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("адрес %s используется DNS/DHCP на %s", ip, name)
			}
		}
	}
	return nil
}

func (m *Manager) restartConfirmedServices() error {
	if m.j.ServicesConfirmed == nil {
		return nil
	}
	if m.services == nil {
		return errors.New("service recovery requires -enable-services")
	}
	if err := m.services.Activate(*m.j.ServicesConfirmed); err != nil {
		return err
	}
	return m.services.Verify(*m.j.ServicesConfirmed)
}
