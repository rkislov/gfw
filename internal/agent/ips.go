package agent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rkislov/gfw/internal/ids"
)

func (m *Manager) SetIPSBackend(b Backend) { m.ips = b }

func ipsSnapshot(c ids.Config) Snapshot {
	if !c.Inline() {
		return Snapshot{}
	}
	names := make([]string, 0, len(c.Interfaces))
	for _, name := range c.Interfaces {
		names = append(names, strconv.Quote(name))
	}
	queue := fmt.Sprintf("counter queue num %d", ids.QueueNumber)
	if c.FailurePolicy == "open" {
		queue += " bypass"
	}
	return Snapshot{Exists: true, Rules: fmt.Sprintf(`table inet gfw_ips {
  comment "gfw-ips-managed-v1"
  set monitored {
    type ifname
    elements = { %s }
  }
  chain inspect {
    type filter hook forward priority 10; policy accept;
    iifname @monitored %s
    iifname != @monitored oifname @monitored %s
  }
}
`, strings.Join(names, ", "), queue, queue)}
}

func (m *Manager) checkIPS(target, prior ids.Config) error {
	if !target.Inline() && !prior.Inline() {
		return nil
	}
	if m.ips == nil {
		return errors.New("Агент не поддерживает таблицу NFQUEUE")
	}
	if target.Inline() {
		firewall, err := m.backend.Snapshot()
		if err != nil {
			return err
		}
		if m.j.Confirmed == nil || !firewall.Exists {
			return errors.New("Сначала примените и подтвердите базовые правила firewall")
		}
	}
	if err := m.ips.Check(ipsSnapshot(target)); err != nil {
		return err
	}
	return m.ips.Check(ipsSnapshot(prior))
}

func (m *Manager) replaceIPS(c ids.Config) error {
	if m.ips == nil {
		return errors.New("Агент не поддерживает таблицу NFQUEUE")
	}
	return m.ips.Replace(ipsSnapshot(c))
}

func (m *Manager) applyIDS(p *idsPending) error {
	if p.Previous.Inline() && !p.Target.Inline() {
		if err := m.replaceIPS(p.Target); err != nil {
			return err
		}
	}
	if err := m.ids.Activate(p.Target); err != nil {
		return err
	}
	if p.Target.Inline() {
		if err := m.replaceIPS(p.Target); err != nil {
			return err
		}
	}
	if p.Previous.Inline() || p.Target.Inline() {
		actual, err := m.ips.Snapshot()
		if err != nil {
			return err
		}
		if actual.Exists != p.Target.Inline() {
			return errors.New("Таблица NFQUEUE не соответствует выбранному режиму")
		}
		p.IPSObserved = &actual
	}
	return m.verifyIDS(p)
}

func (m *Manager) verifyIDS(p *idsPending) error {
	if m.ids == nil {
		return errors.New("Suricata backend disabled")
	}
	if err := m.ids.Verify(p.Target); err != nil {
		return err
	}
	if p.IPSObserved != nil {
		if m.ips == nil {
			return errors.New("Агент не поддерживает таблицу NFQUEUE")
		}
		current, err := m.ips.Snapshot()
		if err != nil {
			return err
		}
		if current != *p.IPSObserved {
			return errors.New("Таблица NFQUEUE изменилась до подтверждения")
		}
	}
	return nil
}

func (m *Manager) restoreIPS(c ids.Config) error {
	if err := m.replaceIPS(c); err != nil {
		return err
	}
	if !c.Inline() {
		m.ipsConfirmed = nil
		return nil
	}
	actual, err := m.ips.Snapshot()
	if err != nil {
		return err
	}
	if !actual.Exists {
		return errors.New("Таблица NFQUEUE отсутствует после восстановления")
	}
	m.ipsConfirmed = &actual
	return nil
}

func (m *Manager) ipsState(c ids.Config, observed *Snapshot, s *IDSState) {
	if !c.Inline() {
		if observed == nil {
			return
		}
	} else {
		s.FailurePolicy = c.FailurePolicy
	}
	s.IPSQueue = ids.QueueNumber
	if m.ips == nil {
		s.IPSError = "Агент не поддерживает таблицу NFQUEUE"
		return
	}
	current, err := m.ips.Snapshot()
	if err != nil {
		s.IPSError = err.Error()
		return
	}
	s.IPSHooked = current.Exists
	switch {
	case observed == nil || current != *observed:
		s.IPSError = "Таблица NFQUEUE изменилась или не восстановлена"
	case current.Exists && s.Runtime.Queue == nil && c.FailurePolicy == "closed":
		s.IPSError = "Слушатель недоступен. Выбранный транзит блокируется."
	case current.Exists && s.Runtime.Queue == nil:
		s.IPSError = "Слушатель недоступен. Выбранный транзит проходит без IPS."
	}
}
