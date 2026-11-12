package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

type tlsState struct {
	current   atomic.Pointer[tls.Certificate]
	fallback  *tls.Certificate
	activeID  string
	pendingID string
	deadline  time.Time
	expiresAt time.Time
	hostname  string
	probe     func(context.Context, *tls.Certificate, string) error
}
type TLSStatus struct {
	Enabled   bool       `json:"enabled"`
	ActiveID  string     `json:"active_id"`
	PendingID string     `json:"pending_id"`
	Deadline  *time.Time `json:"deadline,omitempty"`
	Hostname  string     `json:"hostname"`
}

func (m *Manager) pair(id string, requireValid bool) (*tls.Certificate, error) {
	if id == "" {
		if m.tls.fallback == nil {
			return nil, errors.New("нет исходного сертификата TLS")
		}
		return m.tls.fallback, nil
	}
	x, e := m.get(id)
	if e != nil {
		return nil, e
	}
	if x.RevokedAt != nil {
		return nil, errors.New("сертификат отозван")
	}
	pair, e := validatePair(x.PEM, x.Key, m.now())
	if !requireValid {
		var restored tls.Certificate
		restored, e = tls.X509KeyPair(x.PEM, x.Key)
		if e == nil {
			restored.Leaf, e = x509.ParseCertificate(restored.Certificate[0])
			pair = &restored
		}
	}
	if e != nil {
		return nil, e
	}
	serverUsage := len(pair.Leaf.ExtKeyUsage) == 0
	for _, u := range pair.Leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			serverUsage = true
		}
	}
	if !serverUsage {
		return nil, errors.New("сертификат не разрешён для TLS-сервера")
	}
	return pair, nil
}

// AttachTLS is called before serving requests. Unconfirmed switches never survive restart.
func (m *Manager) AttachTLS(fallback tls.Certificate, probe func(context.Context, *tls.Certificate, string) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tls.fallback = &fallback
	m.tls.probe = probe
	var active, pending, deadline, hostname string
	if e := m.db.QueryRow("SELECT active_id,pending_id,deadline,hostname FROM panel_tls WHERE id=1").Scan(&active, &pending, &deadline, &hostname); e != nil {
		return e
	}
	pair, e := m.pair(active, false)
	if e != nil {
		return fmt.Errorf("confirmed panel TLS: %w", e)
	}
	m.tls.activeID = active
	m.tls.hostname = hostname
	m.tls.current.Store(pair)
	if pending != "" {
		tx, e := m.db.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.Exec("UPDATE panel_tls SET pending_id='',deadline='' WHERE id=1"); e == nil {
			e = audit(tx, "pki.tls.restart.rollback", pending, m.now())
		}
		if e == nil {
			e = tx.Commit()
		}
		return e
	}
	return nil
}
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	pair := m.tls.current.Load()
	if pair == nil {
		return nil, errors.New("panel TLS is disabled")
	}
	return pair, nil
}
func (m *Manager) TLSStatus() TLSStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := TLSStatus{Enabled: m.tls.current.Load() != nil, ActiveID: m.tls.activeID, PendingID: m.tls.pendingID, Hostname: m.tls.hostname}
	if !m.tls.deadline.IsZero() {
		d := m.tls.deadline
		s.Deadline = &d
	}
	return s
}
func (m *Manager) SwitchTLS(ctx context.Context, id, hostname string, seconds int) (TLSStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tls.current.Load() == nil || m.tls.probe == nil {
		return TLSStatus{}, errors.New("смена TLS доступна только на HTTPS-панели")
	}
	if m.tls.pendingID != "" {
		return TLSStatus{}, errors.New("сначала подтвердите или откатите текущую замену TLS")
	}
	if seconds < 30 || seconds > 600 || hostname == "" {
		return TLSStatus{}, errors.New("нужны имя панели и срок 30–600 секунд")
	}
	pair, e := m.pair(id, true)
	if e != nil {
		return TLSStatus{}, e
	}
	if e = pair.Leaf.VerifyHostname(hostname); e != nil {
		return TLSStatus{}, fmt.Errorf("SAN должен покрывать адрес панели %s: %w", hostname, e)
	}
	expiresAt := m.now().Add(time.Duration(seconds) * time.Second)
	deadline := expiresAt.UTC()
	tx, e := m.db.Begin()
	if e != nil {
		return TLSStatus{}, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE panel_tls SET pending_id=?,deadline=? WHERE id=1", id, deadline.Format(time.RFC3339Nano)); e == nil {
		e = audit(tx, "pki.tls.apply", id, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		return TLSStatus{}, e
	}
	m.tls.pendingID = id
	m.tls.deadline = deadline
	m.tls.expiresAt = expiresAt
	m.tls.current.Store(pair)
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e = m.tls.probe(probeCtx, pair, hostname); e != nil {
		rb := m.rollbackTLS("pki.tls.probe.rollback")
		return TLSStatus{}, errors.Join(fmt.Errorf("новое TLS-соединение не прошло проверку: %w", e), rb)
	}
	if !m.now().Before(m.tls.expiresAt) {
		rb := m.rollbackTLS("pki.tls.timeout.rollback")
		return TLSStatus{}, errors.Join(errors.New("истёк срок подтверждения TLS"), rb)
	}
	return TLSStatus{Enabled: true, ActiveID: m.tls.activeID, PendingID: id, Deadline: &deadline, Hostname: hostname}, nil
}
func (m *Manager) ConfirmTLS(id, hostname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tls.pendingID == "" || m.tls.pendingID != id {
		return errors.New("нет ожидающей замены TLS")
	}
	if !m.now().Before(m.tls.expiresAt) {
		rb := m.rollbackTLS("pki.tls.timeout.rollback")
		return errors.Join(errors.New("истёк срок подтверждения TLS"), rb)
	}
	pair, e := m.pair(id, true)
	if e != nil {
		return e
	}
	if e = pair.Leaf.VerifyHostname(hostname); e != nil {
		return e
	}
	if current := m.tls.current.Load(); current == nil || fingerprint(current.Certificate[0]) != fingerprint(pair.Certificate[0]) {
		return errors.New("ожидающий сертификат не установлен в TLS")
	}
	tx, e := m.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE panel_tls SET active_id=?,pending_id='',deadline='',hostname=? WHERE id=1", id, hostname); e == nil {
		e = audit(tx, "pki.tls.confirm", id, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		return e
	}
	m.tls.activeID = id
	m.tls.pendingID = ""
	m.tls.deadline = time.Time{}
	m.tls.hostname = hostname
	return nil
}
func (m *Manager) rollbackTLS(action string) error {
	if m.tls.pendingID == "" {
		return nil
	}
	pair, e := m.pair(m.tls.activeID, false)
	if e != nil {
		return e
	}
	m.tls.current.Store(pair)
	tx, e := m.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE panel_tls SET pending_id='',deadline='' WHERE id=1"); e == nil {
		e = audit(tx, action, m.tls.pendingID, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	if e == nil {
		m.tls.pendingID = ""
		m.tls.deadline = time.Time{}
	}
	return e
}
func (m *Manager) RollbackTLS() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollbackTLS("pki.tls.manual.rollback")
}
func (m *Manager) TickTLS() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tls.pendingID != "" && !m.now().Before(m.tls.expiresAt) {
		return m.rollbackTLS("pki.tls.timeout.rollback")
	}
	return nil
}

// Probe pins the exact leaf, checks SAN/EKU through pair validation, and opens
// a fresh handshake against this process. Trust-store installation is separate.
func Probe(address string) func(context.Context, *tls.Certificate, string) error {
	return func(ctx context.Context, want *tls.Certificate, hostname string) error {
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || fingerprint(cs.PeerCertificates[0].Raw) != fingerprint(want.Certificate[0]) {
				return errors.New("TLS fingerprint mismatch")
			}
			return cs.PeerCertificates[0].VerifyHostname(hostname)
		}}}
		conn, e := dialer.DialContext(ctx, "tcp", address)
		if e == nil {
			e = conn.Close()
		}
		return e
	}
}

// SiteCertificate returns a valid server certificate for a FESS hostname.
func (m *Manager) SiteCertificate(id, hostname string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "" {
		return nil, errors.New("выберите сертификат сайта")
	}
	cert, err := m.pair(id, true)
	if err != nil {
		return nil, err
	}
	if err = cert.Leaf.VerifyHostname(hostname); err != nil {
		return nil, err
	}
	return cert, nil
}
