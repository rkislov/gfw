package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rkislov/gfw/internal/policy"
)

type flowBackend interface {
	Backend
	Compatible() error
	Counters() (FlowCounters, error)
}

type FlowCounters struct {
	TCP            uint64 `json:"tcp"`
	UDP            uint64 `json:"udp"`
	IngressPackets uint64 `json:"ingress_packets"`
	IngressBytes   uint64 `json:"ingress_bytes"`
}

type FlowExclusion struct {
	Interface string `json:"interface"`
	Reason    string `json:"reason"`
}

type FlowState struct {
	Available  bool            `json:"available"`
	Configured bool            `json:"configured"`
	Active     bool            `json:"active"`
	Revision   int64           `json:"revision"`
	Rules      int             `json:"rules"`
	Interfaces []string        `json:"interfaces"`
	Excluded   []FlowExclusion `json:"excluded"`
	Reason     string          `json:"reason,omitempty"`
	Counters   *FlowCounters   `json:"counters,omitempty"`
}

type flowRuntime struct {
	desired   Snapshot
	observed  Snapshot
	state     FlowState
	nextCheck time.Time
}

func (m *Manager) SetFlowBackend(b flowBackend) { m.flow = b }

func (m *Manager) flowConfig(c policy.Config, revision int64) (Snapshot, FlowState, error) {
	s := FlowState{Available: m.flow != nil, Configured: c.Flowtable != nil, Revision: revision, Rules: c.FlowRuleCount(), Interfaces: []string{}, Excluded: []FlowExclusion{}}
	if c.Flowtable == nil {
		return Snapshot{}, s, nil
	}
	if m.flow == nil {
		return Snapshot{}, s, errors.New("Linux-агент не поддерживает ускорение транзита")
	}
	if s.Rules == 0 {
		s.Reason = "В политике нет включённых разрешающих правил TCP/UDP с ускорением"
		return Snapshot{}, s, nil
	}
	if m.j.IPsecConfirmed != nil {
		for _, tunnel := range m.j.IPsecConfirmed.Tunnels {
			if tunnel.Enabled {
				s.Reason = "Ускорение приостановлено на время работы IPsec"
				return Snapshot{}, s, nil
			}
		}
	}
	if err := m.flow.Compatible(); err != nil {
		s.Reason = err.Error()
		return Snapshot{}, s, nil
	}
	ports, err := routedFlowPorts()
	if err != nil {
		return Snapshot{}, s, err
	}
	ids := m.idsConfig()
	for _, name := range c.Flowtable.Interfaces {
		switch {
		case ids.Inline() && slices.Contains(ids.Interfaces, name):
			s.Excluded = append(s.Excluded, FlowExclusion{name, "Suricata IPS"})
		case !ports[name]:
			s.Excluded = append(s.Excluded, FlowExclusion{name, "Требуется включённый самостоятельный Ethernet-порт"})
		default:
			s.Interfaces = append(s.Interfaces, name)
		}
	}
	if len(s.Interfaces) < 2 {
		s.Reason = "Для ускорения нужны два подходящих интерфейса без IPS"
		return Snapshot{}, s, nil
	}
	text := policy.CompileFlow(c, m.safety, s.Interfaces)
	return Snapshot{Exists: text != "", Rules: text}, s, nil
}

func (m *Manager) flowConfigured() bool {
	return m.flowRuntime.observed.Exists || m.flowRuntime.desired.Exists ||
		m.j.FirewallConfig != nil && m.j.FirewallConfig.Flowtable != nil ||
		m.j.Pending != nil && m.j.Pending.FirewallConfig != nil && m.j.Pending.FirewallConfig.Flowtable != nil
}

func affectsFlow(p *pending) bool {
	return p.FirewallConfig != nil || p.Network != nil || p.IPsec != nil || p.XDP != nil ||
		p.IDS != nil && (p.IDS.Previous.Inline() || p.IDS.Target.Inline())
}

func (m *Manager) pauseFlow() error {
	if m.flow == nil || !m.flowConfigured() {
		return nil
	}
	current, err := m.flow.Snapshot()
	if err != nil {
		return err
	}
	if current.Exists {
		if err = m.flow.Replace(Snapshot{}); err != nil {
			return err
		}
	}
	m.flowRuntime = flowRuntime{state: FlowState{Available: true, Configured: true, Revision: m.j.ConfirmedRevision,
		Interfaces: []string{}, Excluded: []FlowExclusion{}, Reason: "Ускорение приостановлено на время применения изменений"}}
	return nil
}

func (m *Manager) activateFlow(c policy.Config, revision int64) error {
	target, state, err := m.flowConfig(c, revision)
	m.flowRuntime.state = state
	if err != nil {
		m.flowRuntime.state.Reason = err.Error()
		if m.flow != nil {
			return errors.Join(err, m.flow.Replace(Snapshot{}))
		}
		return err
	}
	if m.flow == nil {
		return nil
	}
	if target == m.flowRuntime.desired && m.flowRuntime.observed.Exists {
		current, e := m.flow.Snapshot()
		if e == nil && current == m.flowRuntime.observed {
			m.flowRuntime.state.Active = true
			return nil
		}
	}
	if !target.Exists && !m.flowRuntime.observed.Exists {
		current, e := m.flow.Snapshot()
		if e != nil {
			m.flowRuntime.state.Reason = e.Error()
			return e
		}
		if !current.Exists {
			return nil
		}
	}
	m.flowRuntime.desired, m.flowRuntime.observed = Snapshot{}, Snapshot{}
	if err = m.flow.Replace(target); err == nil && target.Exists {
		m.flowRuntime.observed, err = m.flow.Snapshot()
		if err == nil && !m.flowRuntime.observed.Exists {
			err = errors.New("таблица ускорения отсутствует после загрузки")
		}
	}
	if err != nil {
		m.flowRuntime.state.Reason = err.Error()
		// A timed-out update can leave a live table. Remove it before continuing.
		return errors.Join(err, m.flow.Replace(Snapshot{}))
	}
	m.flowRuntime.desired = target
	m.flowRuntime.state.Active = target.Exists
	return nil
}

func (m *Manager) verifyFlow() error {
	if m.flow == nil || !m.flowRuntime.observed.Exists {
		return nil
	}
	current, err := m.flow.Snapshot()
	if err != nil {
		return err
	}
	if current != m.flowRuntime.observed {
		return errors.New("таблица ускорения изменилась до подтверждения")
	}
	return m.flow.Compatible()
}

func (m *Manager) maintainFlow() error {
	if m.flow == nil {
		return nil
	}
	if p := m.j.Pending; p != nil && affectsFlow(p) {
		return nil
	}
	if !m.flowConfigured() {
		m.flowRuntime = flowRuntime{}
		return nil
	}
	if m.now().Before(m.flowRuntime.nextCheck) {
		return nil
	}
	m.flowRuntime.nextCheck = m.now().Add(5 * time.Second)
	if m.j.FirewallConfig == nil {
		return m.pauseFlow()
	}
	current, err := m.backend.Snapshot()
	if err != nil || !current.Exists {
		stopErr := m.pauseFlow()
		m.flowRuntime.state.Reason = "Ускорение приостановлено: действующая политика firewall недоступна"
		return errors.Join(err, stopErr)
	}
	return m.activateFlow(*m.j.FirewallConfig, m.j.ConfirmedRevision)
}

func (m *Manager) FlowState() FlowState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.flowRuntime.state
	out.Available = m.flow != nil
	if out.Interfaces == nil {
		out.Interfaces = []string{}
	}
	if out.Excluded == nil {
		out.Excluded = []FlowExclusion{}
	}
	if out.Active && m.flow != nil {
		counts, err := m.flow.Counters()
		if err == nil {
			out.Counters = &counts
		} else {
			out.Reason = err.Error()
		}
	}
	return out
}

// Compatible only permits a fast path when GFW owns the forwarding hooks.
func (n NFT) Compatible() error {
	raw, err := n.run("", "-j", "-t", "list", "ruleset")
	if err != nil {
		return err
	}
	var doc struct {
		NFTables []struct {
			Chain *struct{ Family, Table, Hook string }   `json:"chain"`
			Table *struct{ Family, Name, Comment string } `json:"table"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	owners := map[string]string{}
	for _, entry := range doc.NFTables {
		if t := entry.Table; t != nil {
			owners[t.Family+"/"+t.Name] = t.Comment
		}
	}
	trusted := map[string]string{"inet/gfw": policy.Owner, "inet/" + policy.FlowTableName: policy.FlowOwner, "inet/gfw_ips": "gfw-ips-managed-v1"}
	for _, entry := range doc.NFTables {
		c := entry.Chain
		if c == nil {
			continue
		}
		switch c.Hook {
		case "ingress", "prerouting", "forward", "postrouting", "egress":
			key := c.Family + "/" + c.Table
			if owner, ok := trusted[key]; !ok || owner != owners[key] {
				return fmt.Errorf("ускорение приостановлено: таблица %s обрабатывает транзит", key)
			}
		}
	}
	return nil
}

func (n NFT) Counters() (FlowCounters, error) {
	var out FlowCounters
	values, err := n.namedCounters(policy.FlowTableName)
	if err != nil {
		return out, err
	}
	for _, name := range []string{policy.FlowTCP, policy.FlowUDP, policy.FlowBefore, policy.FlowAfter} {
		if _, ok := values[name]; !ok {
			return out, errors.New("счётчики ускорения недоступны")
		}
	}
	before, after := values[policy.FlowBefore], values[policy.FlowAfter]
	out.TCP = values[policy.FlowTCP].Packets
	out.UDP = values[policy.FlowUDP].Packets
	out.IngressPackets = max(before.Packets, after.Packets) - after.Packets
	out.IngressBytes = max(before.Bytes, after.Bytes) - after.Bytes
	return out, nil
}
