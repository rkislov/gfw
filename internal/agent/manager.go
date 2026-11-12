package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/capture"
	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/traffic"
	"github.com/rkislov/gfw/internal/wireguard"
	"github.com/rkislov/gfw/internal/xdpguard"
)

var ErrConflict = errors.New("operation conflict")

type ApplyRequest struct {
	ID             string        `json:"id"`
	Revision       int64         `json:"revision"`
	TimeoutSeconds int           `json:"timeout_seconds"`
	Config         policy.Config `json:"config"`
}
type Record struct {
	Kind      string    `json:"kind,omitempty"`
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Status    string    `json:"status"`
	Deadline  time.Time `json:"deadline"`
	CreatedAt time.Time `json:"created_at"`
	Error     string    `json:"error,omitempty"`
	Digest    string    `json:"digest"`
}
type pending struct {
	XDP            *xdpPending       `json:"xdp,omitempty"`
	IDS            *idsPending       `json:"ids,omitempty"`
	IPsec          *ipsecPending     `json:"ipsec,omitempty"`
	OpenVPN        *openvpnPending   `json:"openvpn,omitempty"`
	WireGuard      *wireguardPending `json:"wireguard,omitempty"`
	Services       *servicesPending  `json:"services,omitempty"`
	FirewallConfig *policy.Config    `json:"firewall_config,omitempty"`
	Network        *networkPending   `json:"network,omitempty"`
	Record         Record            `json:"record"`
	Previous       Snapshot          `json:"previous"`
	Target         Snapshot          `json:"target"`
	Observed       Snapshot          `json:"observed"`
}
type journal struct {
	XDPConfirmed       *xdpguard.Config       `json:"xdp_confirmed,omitempty"`
	XDPRevision        int64                  `json:"xdp_revision,omitempty"`
	IDSConfirmed       *ids.Config            `json:"ids_confirmed,omitempty"`
	IDSRevision        int64                  `json:"ids_revision,omitempty"`
	IPsecConfirmed     *ipsec.Config          `json:"ipsec_confirmed,omitempty"`
	IPsecRevision      int64                  `json:"ipsec_revision"`
	OpenVPNConfirmed   *openvpn.RuntimeConfig `json:"openvpn_confirmed,omitempty"`
	OpenVPNRevision    int64                  `json:"openvpn_revision"`
	WireGuardConfirmed *wireguard.Config      `json:"wireguard_confirmed,omitempty"`
	WireGuardRevision  int64                  `json:"wireguard_revision"`
	ServicesConfirmed  *services.Config       `json:"services_confirmed,omitempty"`
	ServicesRevision   int64                  `json:"services_revision"`
	FirewallConfig     *policy.Config         `json:"firewall_config,omitempty"`
	NetworkBackend     string                 `json:"network_backend,omitempty"`
	NetworkConfirmed   *netconfig.Config      `json:"network_confirmed,omitempty"`
	NetworkRevision    int64                  `json:"network_revision"`
	Safety             policy.Safety          `json:"safety"`
	Version            int                    `json:"version"`
	Confirmed          *Snapshot              `json:"confirmed,omitempty"`
	ConfirmedRevision  int64                  `json:"confirmed_revision"`
	Pending            *pending               `json:"pending,omitempty"`
	History            []Record               `json:"history"`
}
type State struct {
	SecurityFeed      *feed.FilterSummary `json:"security_feed,omitempty"`
	Enabled           bool                `json:"enabled"`
	ConfirmedRevision int64               `json:"confirmed_revision"`
	Pending           *Record             `json:"pending,omitempty"`
	History           []Record            `json:"history"`
	Safety            policy.Safety       `json:"safety"`
}
type Plan struct {
	NFTables        string        `json:"nftables"`
	FlowNFTables    string        `json:"flow_nftables,omitempty"`
	CanApply        bool          `json:"can_apply"`
	KernelValidated bool          `json:"kernel_validated"`
	Safety          policy.Safety `json:"safety"`
	Warnings        []string      `json:"warnings"`
}
type Manager struct {
	flow         flowBackend
	flowRuntime  flowRuntime
	xdp          xdpguard.Backend
	xdpError     string
	xdpRetry     time.Time
	capture      *capture.Manager
	traffic      *traffic.Collector
	ips          Backend
	ipsConfirmed *Snapshot
	ids          ids.Backend
	ipsec        ipsec.Backend
	stopping     bool
	openvpn      openvpn.Backend
	wireguard    wireguard.Backend
	services     services.Backend
	network      netconfig.Backend
	mu           sync.Mutex
	backend      Backend
	disk         *diskJournal
	j            journal
	safety       policy.Safety
	now          func() time.Time
	validateLAN  func() error
	save         func(journal) error
	expiresAt    time.Time
}

func (m *Manager) expired() bool {
	if !m.expiresAt.IsZero() {
		return !m.now().Before(m.expiresAt)
	}
	return m.j.Pending != nil && !m.now().Before(m.j.Pending.Record.Deadline)
}

func NewManager(dir string, b Backend, safety policy.Safety) (*Manager, error) {
	if err := safety.Validate(); err != nil {
		return nil, err
	}
	d, err := openJournal(dir)
	if err != nil {
		return nil, err
	}
	j, err := d.load()
	if err != nil {
		d.close()
		return nil, err
	}
	if j.Safety.LANInterface != "" && j.Safety != safety {
		d.close()
		return nil, errors.New("LAN safety configuration differs from the recovery journal; explicit migration is required")
	}
	j.Safety = safety
	m := &Manager{backend: b, disk: d, j: j, safety: safety, now: time.Now, save: d.save}
	m.validateLAN = func() error {
		l, err := net.InterfaceByName(safety.LANInterface)
		if err != nil {
			return fmt.Errorf("LAN interface: %w", err)
		}
		if l.Flags&net.FlagLoopback != 0 || l.Flags&net.FlagUp == 0 {
			return errors.New("LAN interface must be non-loopback and administratively UP")
		}
		return nil
	}
	return m, nil
}
func (m *Manager) Close() error { return m.disk.close() }
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := State{Enabled: true, ConfirmedRevision: m.j.ConfirmedRevision, Safety: m.safety, History: append([]Record{}, m.j.History...)}
	if m.j.FirewallConfig != nil {
		s.SecurityFeed = m.j.FirewallConfig.SecurityFeed.Summary()
	}
	if m.j.Pending != nil {
		r := m.j.Pending.Record
		s.Pending = &r
	}
	return s
}
func (m *Manager) plan(c policy.Config, revision int64) (Plan, error) {
	if err := m.checkXDPZones(m.xdpConfig(), &c); err != nil {
		return Plan{}, err
	}
	var text string
	var err error
	if m.traffic != nil {
		text, err = policy.CompileLogged(c, m.safety, revision)
	} else {
		text, err = policy.CompileManaged(c, m.safety)
	}
	if err != nil {
		return Plan{}, err
	}
	if err = m.validateLAN(); err != nil {
		return Plan{}, err
	}
	for _, z := range c.Zones {
		for _, name := range z.Interfaces {
			link, err := net.InterfaceByName(name)
			if err != nil || link.Flags&net.FlagLoopback != 0 {
				return Plan{}, fmt.Errorf("интерфейс %s зоны %s не найден или недопустим", name, z.Name)
			}
		}
	}
	if err = m.backend.Check(Snapshot{true, text}); err != nil {
		return Plan{}, err
	}
	warnings := []string{"Доступ к панели через LAN защищён системным правилом перед пользовательскими правилами.", "Другие таблицы nftables и сетевые настройки могут ограничить доступ независимо от GFW.", "После применения подтвердите доступ до окончания таймера, иначе агент восстановит предыдущие правила."}
	if f := c.SecurityFeed; f != nil {
		warnings = append(warnings, fmt.Sprintf("Security Feed: %d сетей, %d исключений; блокировка транзита по адресу источника или назначения.", len(f.Values), len(f.Exceptions)))
	}
	var flowText string
	if c.Flowtable != nil {
		flow, status, e := m.flowConfig(c, revision)
		if e != nil {
			return Plan{}, e
		}
		if flow.Exists {
			flowText = flow.Rules
			if e = m.flow.Check(flow); e != nil {
				return Plan{}, fmt.Errorf("проверка nftables flowtable: %w", e)
			}
		}
		if status.Reason != "" {
			warnings = append(warnings, status.Reason)
		}
		for _, excluded := range status.Excluded {
			warnings = append(warnings, excluded.Interface+": "+excluded.Reason)
		}
	}
	if c.Stateful {
		warnings = append(warnings, "Stateful использует младшие 64 бита conntrack labels; их нельзя совместно использовать с другими управляющими системами. Новая политика повторно проверяет исходное направление соединений.")
	}
	if len(c.NAT) > 0 {
		warnings = append(warnings, "NAT применяется к новым соединениям. Существующие отображения conntrack не очищаются глобально; автоматический доступ для проброса ограничен его исходным и преобразованным адресом/портом.")
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) != "1" {
		warnings = append(warnings, "IPv4-маршрутизация в ядре выключена. Транзит и NAT потребуют включения профиля маршрутизатора администратором.")
	}
	return Plan{NFTables: text, FlowNFTables: flowText, CanApply: m.j.Pending == nil, KernelValidated: true, Safety: m.safety, Warnings: warnings}, nil
}
func (m *Manager) Plan(c policy.Config) (Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.plan(c, 0)
}

func (m *Manager) Apply(req ApplyRequest) (Record, error) {
	req.Config = policy.Canonical(req.Config)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return Record{}, fmt.Errorf("%w: agent shutting down", ErrConflict)
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(req.ID) || req.Revision < 1 || req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		return Record{}, errors.New("id, revision and timeout 30–600 seconds are required")
	}
	raw, _ := json.Marshal(req)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if p := m.j.Pending; p != nil && p.Record.ID == req.ID {
		if p.Record.Digest != digest {
			return Record{}, fmt.Errorf("%w: id reused with different payload", ErrConflict)
		}
		return p.Record, nil
	}
	for _, r := range m.j.History {
		if r.ID == req.ID {
			if r.Digest != digest {
				return Record{}, fmt.Errorf("%w: id reused with different payload", ErrConflict)
			}
			return r, nil
		}
	}
	if m.j.Pending != nil {
		return Record{}, fmt.Errorf("%w: resolve pending change first", ErrConflict)
	}
	plan, err := m.plan(req.Config, req.Revision)
	if err != nil {
		return Record{}, err
	}
	previous, err := m.backend.Snapshot()
	if err != nil {
		return Record{}, err
	}
	if err = m.backend.Check(previous); err != nil {
		return Record{}, fmt.Errorf("rollback snapshot is not restorable: %w", err)
	}
	now := m.now()
	r := Record{Kind: "firewall", ID: req.ID, Revision: req.Revision, Status: "applying", CreatedAt: now.UTC(), Digest: digest}
	r.Deadline = r.CreatedAt.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	m.expiresAt = now.Add(time.Duration(req.TimeoutSeconds) * time.Second)
	p := &pending{Record: r, Previous: previous, Target: Snapshot{true, plan.NFTables}, FirewallConfig: &req.Config}
	if m.j.Version < 3 {
		m.j.Version = 3
	}
	if req.Config.Flowtable != nil {
		m.j.Version = max(m.j.Version, 12)
	}
	m.j.Pending = p
	if err = m.save(m.j); err != nil {
		m.j.Pending = nil
		return Record{}, fmt.Errorf("persist before apply: %w", err)
	}
	// Once the durable intent exists, client cancellation cannot interrupt the
	// transaction. Ambiguous nft timeouts always trigger compensating rollback.
	if err = m.pauseFlow(); err == nil {
		err = m.backend.Replace(p.Target)
	}
	if err == nil {
		p.Observed, err = m.backend.Snapshot()
		if err == nil && !p.Observed.Exists {
			err = errors.New("applied table is missing")
		}
	}
	if err == nil && (m.flowConfigured() || req.Config.Flowtable != nil) {
		err = m.activateFlow(req.Config, req.Revision)
	}
	if err != nil {
		cause := err
		_, rbErr := m.rollback("apply failed: " + err.Error())
		return Record{}, errors.Join(cause, rbErr)
	}
	p.Record.Status = "pending"
	if err = m.save(m.j); err != nil {
		cause := err
		_, rbErr := m.rollback("persist after apply failed: " + err.Error())
		return Record{}, errors.Join(cause, rbErr)
	}
	if m.expired() {
		_, err = m.rollback("deadline expired during apply")
		return Record{}, errors.Join(ErrConflict, err)
	}
	return p.Record, nil
}
func (m *Manager) appendHistory(r Record) {
	m.j.History = append(m.j.History, r)
	if len(m.j.History) > 100 {
		m.j.History = append([]Record{}, m.j.History[len(m.j.History)-100:]...)
	}
}
func (m *Manager) rollback(reason string) (Record, error) {
	p := m.j.Pending
	if p == nil {
		return Record{}, fmt.Errorf("%w: no pending change", ErrConflict)
	}
	p.Record.Status = "rolling_back"
	p.Record.Error = reason
	// Even if this write fails, the earlier durable intent still instructs the
	// next process to restore Previous. Restoring connectivity takes priority.
	_ = m.save(m.j)
	var err error
	if affectsFlow(p) {
		err = m.pauseFlow()
	}
	if err != nil {
		p.Record.Status = "rollback_failed"
		p.Record.Error = reason + ": " + err.Error()
		_ = m.save(m.j)
		return p.Record, err
	}
	if p.XDP != nil {
		err = m.restoreXDP(p.XDP.Previous)
	} else if p.IDS != nil {
		if p.IDS.Previous.Inline() || p.IDS.Target.Inline() {
			err = m.restoreIPS(p.IDS.Previous)
		}
		if err == nil {
			if e := m.restoreIDS(p.IDS.Previous); e != nil {
				p.Record.Error += "; Suricata: " + e.Error()
			}
		}
	} else if p.IPsec != nil {
		if m.ipsec == nil {
			err = errors.New("IPsec backend disabled")
		} else {
			err = m.ipsec.Activate(p.IPsec.Previous, p.IPsec.Target)
		}
	} else if p.OpenVPN != nil {
		if m.openvpn == nil {
			err = errors.New("OpenVPN backend disabled")
		} else {
			err = m.openvpn.Activate(p.OpenVPN.Previous, p.OpenVPN.Target)
			if err == nil {
				err = m.restartConfirmedServices()
			}
		}
	} else if p.WireGuard != nil {
		if m.wireguard == nil {
			err = errors.New("WireGuard backend disabled")
		} else {
			err = m.wireguard.Activate(p.WireGuard.Previous, p.WireGuard.Target)
			if err == nil {
				err = m.restartConfirmedServices()
			}
		}
	} else if p.Services != nil {
		if m.services == nil {
			err = errors.New("service backend disabled")
		} else {
			err = m.services.Activate(p.Services.Previous)
			if err == nil {
				err = m.services.Verify(p.Services.Previous)
			}
		}
	} else if p.Network != nil {
		if m.network == nil {
			err = errors.New("network recovery backend is disabled")
		} else {
			err = m.network.Restore(p.Network.Previous)
			if err == nil {
				err = m.restartNetworkConsumers()
			}
		}
	} else {
		err = m.backend.Replace(p.Previous)
	}
	if err == nil && p.Network == nil && p.Services == nil && p.WireGuard == nil && p.OpenVPN == nil && p.IPsec == nil && p.IDS == nil && p.XDP == nil {
		var actual Snapshot
		actual, err = m.backend.Snapshot()
		if err == nil && actual != p.Previous {
			err = errors.New("rollback verification failed")
		}
	}
	if err != nil {
		p.Record.Status = "rollback_failed"
		p.Record.Error = reason + "; " + err.Error()
		_ = m.save(m.j)
		return p.Record, err
	}
	oldHistory := append([]Record{}, m.j.History...)
	r := p.Record
	r.Status = "rolled_back"
	m.j.Pending = nil
	m.appendHistory(r)
	if err = m.save(m.j); err != nil {
		m.j.History = oldHistory
		m.j.Pending = p
		p.Record.Status = "rollback_failed"
		p.Record.Error = "rules restored, but completion was not persisted: " + err.Error()
		return p.Record, err
	}
	return r, nil
}
func (m *Manager) Confirm(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.j.Pending
	if p == nil {
		for _, r := range m.j.History {
			if r.ID == id && r.Status == "confirmed" {
				return r, nil
			}
		}
		return Record{}, fmt.Errorf("%w: change is not awaiting confirmation", ErrConflict)
	}
	if p.Record.ID != id || p.Record.Status != "pending" {
		return Record{}, fmt.Errorf("%w: wrong change or status", ErrConflict)
	}
	if m.expired() {
		_, err := m.rollback("confirmation deadline expired")
		return Record{}, errors.Join(ErrConflict, err)
	}
	var err error
	drift := false
	if p.XDP != nil {
		err = m.verifyXDP(p.XDP.Target)
	} else if p.IDS != nil {
		err = m.verifyIDS(p.IDS)
	} else if p.IPsec != nil {
		if m.ipsec == nil {
			err = errors.New("IPsec backend disabled")
		} else {
			err = m.ipsec.Verify(p.IPsec.Target)
			if err == nil {
				var statuses []ipsec.Status
				statuses, err = m.ipsec.Status(p.IPsec.Target)
				for _, status := range statuses {
					if status.Blocked != "" {
						err = errors.New(status.Blocked)
						break
					}
				}
			}
		}
	} else if p.OpenVPN != nil {
		if m.openvpn == nil {
			err = errors.New("OpenVPN backend disabled")
		} else {
			err = m.openvpn.Verify(p.OpenVPN.Target)
			if err == nil {
				statuses, e := m.openvpn.Status(p.OpenVPN.Target)
				err = e
				for _, s := range statuses {
					if s.Blocked != "" {
						for _, i := range p.OpenVPN.Target.Instances {
							if i.ID == s.ID && i.Enabled {
								err = errors.New("сертификат или CRL недействителен; подтверждение запрещено")
							}
						}
					}
				}
			}
			if err == nil && m.j.ServicesConfirmed != nil {
				if m.services == nil {
					err = errors.New("service backend disabled")
				} else {
					err = m.services.Verify(*m.j.ServicesConfirmed)
				}
			}
		}
	} else if p.WireGuard != nil {
		if m.wireguard == nil {
			err = errors.New("WireGuard backend disabled")
		} else {
			err = m.wireguard.Verify(p.WireGuard.Target)
			if err == nil && m.j.ServicesConfirmed != nil {
				if m.services == nil {
					err = errors.New("service backend disabled")
				} else {
					err = m.services.Verify(*m.j.ServicesConfirmed)
				}
			}
		}
	} else if p.Services != nil {
		if m.services == nil {
			err = errors.New("service backend disabled")
		} else {
			err = m.services.Verify(p.Services.Target)
		}
	} else if p.Network != nil {
		if m.network == nil {
			err = errors.New("network backend disabled")
		} else {
			err = m.network.Verify(p.Network.Target)
			if err == nil && m.j.OpenVPNConfirmed != nil {
				if m.openvpn == nil {
					err = errors.New("OpenVPN disabled")
				} else {
					err = m.openvpn.Verify(*m.j.OpenVPNConfirmed)
				}
			}
			if err == nil && m.j.ServicesConfirmed != nil {
				if m.services == nil {
					err = errors.New("service backend disabled")
				} else {
					err = m.services.Verify(*m.j.ServicesConfirmed)
				}
			}
		}
	} else {
		var current Snapshot
		current, err = m.backend.Snapshot()
		drift = current != p.Observed
		if err == nil && !drift {
			err = m.verifyFlow()
		}
	}
	if err != nil || drift {
		_, rb := m.rollback("live table changed before confirmation")
		return Record{}, errors.Join(ErrConflict, err, rb)
	}
	// Recheck after potentially slow kernel reads; never confirm past deadline.
	if m.expired() {
		_, err := m.rollback("confirmation deadline expired")
		return Record{}, errors.Join(ErrConflict, err)
	}
	old := m.j
	old.History = append([]Record{}, m.j.History...)
	if p.XDP != nil {
		m.j.XDPConfirmed = &p.XDP.Target
		m.j.XDPRevision = p.Record.Revision
	} else if p.IDS != nil {
		m.j.IDSConfirmed = &p.IDS.Target
		m.j.IDSRevision = p.Record.Revision
	} else if p.IPsec != nil {
		m.j.IPsecConfirmed = &p.IPsec.Target
		m.j.IPsecRevision = p.Record.Revision
	} else if p.OpenVPN != nil {
		m.j.OpenVPNConfirmed = &p.OpenVPN.Target
		m.j.OpenVPNRevision = p.Record.Revision
	} else if p.WireGuard != nil {
		m.j.WireGuardConfirmed = &p.WireGuard.Target
		m.j.WireGuardRevision = p.Record.Revision
	} else if p.Services != nil {
		m.j.ServicesConfirmed = &p.Services.Target
		m.j.ServicesRevision = p.Record.Revision
	} else if p.Network != nil {
		m.j.NetworkConfirmed = &p.Network.Target
		if p.Network.Previous.Netplan != nil {
			m.j.NetworkBackend = "netplan"
		}
		m.j.NetworkRevision = p.Record.Revision
	} else {
		m.j.Confirmed = &p.Target
		m.j.ConfirmedRevision = p.Record.Revision
		m.j.FirewallConfig = p.FirewallConfig
	}
	m.j.Pending = nil
	r := p.Record
	r.Status = "confirmed"
	m.appendHistory(r)
	if err = m.save(m.j); err != nil {
		m.j = old
		return Record{}, fmt.Errorf("confirmation not durable: %w", err)
	}
	if p.IDS != nil {
		m.ipsConfirmed = nil
		if p.IDS.Target.Inline() {
			m.ipsConfirmed = p.IDS.IPSObserved
		}
	}
	return r, nil
}
func (m *Manager) Rollback(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.j.Pending == nil {
		for _, r := range m.j.History {
			if r.ID == id && r.Status == "rolled_back" {
				return r, nil
			}
		}
		return Record{}, fmt.Errorf("%w: no pending change", ErrConflict)
	}
	if m.j.Pending.Record.ID != id {
		return Record{}, fmt.Errorf("%w: wrong change", ErrConflict)
	}
	return m.rollback("manual rollback")
}

// Recover runs before accepting requests. Any unconfirmed intent is rolled back
// immediately on process restart, including a crash between nft and journal fsync.
// A previously confirmed table is restored at boot without touching other tables.
func (m *Manager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.j.NetworkConfirmed != nil {
		backend := m.j.NetworkBackend
		if backend == "" {
			backend = "etcnet"
		}
		if m.networkMode() != backend {
			return fmt.Errorf("для восстановления сети требуется backend %s", backend)
		}
	}
	if p := m.j.Pending; p != nil && p.Network != nil {
		if (p.Network.Previous.Netplan != nil) != (m.networkMode() == "netplan") {
			return errors.New("сетевой backend не соответствует журналу ожидающего изменения")
		}
	}
	if err := m.pauseFlow(); err != nil {
		return err
	}
	// Restore the confirmed filter before opening any VPN/service listeners.
	// nft iifname/oifname rules are safe even before network interfaces return.
	if m.j.Confirmed != nil {
		if e := m.backend.Check(*m.j.Confirmed); e != nil {
			return e
		}
		if e := m.backend.Replace(*m.j.Confirmed); e != nil {
			return e
		}
	}

	if m.j.Pending != nil && (m.j.Pending.Services != nil || m.j.Pending.WireGuard != nil || m.j.Pending.OpenVPN != nil || m.j.Pending.IPsec != nil) && m.j.NetworkConfirmed != nil {
		if m.network == nil {
			return errors.New("network recovery requires -enable-network")
		}
		if err := m.network.Verify(*m.j.NetworkConfirmed); err != nil {
			if err = m.network.Activate(*m.j.NetworkConfirmed, *m.j.NetworkConfirmed); err != nil {
				return err
			}
		}
	}
	if p := m.j.Pending; p != nil {
		_, err := m.rollback("agent restart: unconfirmed change")
		if err != nil && p.IDS == nil {
			return err
		}
	}
	if m.j.NetworkConfirmed != nil {
		if m.network == nil {
			return errors.New("network recovery requires -enable-network")
		}
		if err := m.network.Verify(*m.j.NetworkConfirmed); err != nil {
			if err = m.network.Activate(*m.j.NetworkConfirmed, *m.j.NetworkConfirmed); err != nil {
				return err
			}
		}
	}
	if m.j.WireGuardConfirmed != nil {
		if m.wireguard == nil {
			return errors.New("WireGuard recovery requires -enable-wireguard")
		}
		if err := m.wireguard.Verify(*m.j.WireGuardConfirmed); err != nil {
			if err = m.wireguard.Activate(*m.j.WireGuardConfirmed, *m.j.WireGuardConfirmed); err != nil {
				return err
			}
		}
	}
	if m.j.IPsecConfirmed != nil {
		if m.ipsec == nil {
			return errors.New("IPsec recovery requires -enable-ipsec")
		}
		// An unavailable peer or IKE daemon must not block access to the panel.
		_ = m.ipsec.Activate(*m.j.IPsecConfirmed, *m.j.IPsecConfirmed)
	}

	if m.j.OpenVPNConfirmed != nil {
		if m.openvpn == nil {
			return errors.New("OpenVPN recovery requires -enable-openvpn")
		}
		// A disconnected VPN must not prevent restoration of firewall and LAN.
		_ = m.openvpn.Activate(*m.j.OpenVPNConfirmed, *m.j.OpenVPNConfirmed)
	}

	if m.j.ServicesConfirmed != nil {
		if m.services == nil {
			return errors.New("service recovery requires -enable-services")
		}
		if err := m.services.Activate(*m.j.ServicesConfirmed); err != nil {
			return err
		}
	}
	if m.j.Pending == nil && m.j.IDSConfirmed != nil {
		c := *m.j.IDSConfirmed
		if c.Inline() && m.ipsConfirmed == nil {
			_ = m.restoreIPS(c)
		}
		if m.ids != nil && m.ids.Verify(c) != nil {
			_ = m.restoreIDS(c)
		}
	}
	if m.j.Confirmed != nil {
		_ = m.restoreXDP(m.xdpConfig())
		_ = m.maintainFlow()
		if err := m.validateLAN(); err != nil {
			return err
		}
		return nil
	}
	current, err := m.backend.Snapshot()
	if err != nil {
		return err
	}
	if current.Exists {
		return errors.New("GFW table exists but no recovery journal is available")
	}
	return nil
}

// Tick is called independently of gfwd. Failed rollbacks remain pending and are
// retried every second; no new apply is allowed while recovery is unresolved.
func (m *Manager) Tick() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return nil
	}
	p := m.j.Pending
	if p != nil && (p.Record.Status != "pending" || m.expired()) {
		_, err := m.rollback("confirmation timeout or recovery retry")
		return err
	}
	result := errors.Join(m.maintainXDP(), m.maintainFlow())
	if m.openvpn != nil {
		result = errors.Join(result, m.openvpn.Maintain(m.openVPNActive()))
	}
	if m.ipsec != nil {
		result = errors.Join(result, m.ipsec.Maintain(m.ipsecActive()))
	}
	return result
}
func (m *Manager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopping = true
	var err error
	if m.j.Pending != nil {
		_, err = m.rollback("agent shutdown: unconfirmed change")
	}
	return errors.Join(err, m.pauseFlow())
}
