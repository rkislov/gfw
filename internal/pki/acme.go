package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/rkislov/gfw/internal/engines/fess/acmeissue"
	"github.com/rkislov/gfw/internal/engines/fess/certs"
	"golang.org/x/crypto/acme"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type ProfileRequest struct {
	Name            string   `json:"name"`
	DirectoryURL    string   `json:"directory_url"`
	Email           string   `json:"email"`
	Domains         []string `json:"domains"`
	TOSAgreed       bool     `json:"tos_agreed"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBeforeDays int      `json:"renew_before_days"`
}
type Profile struct {
	ID string `json:"id"`
	ProfileRequest
	AccountURI string `json:"account_uri"`
	LatestID   string `json:"latest_id"`
	LastError  string `json:"last_error,omitempty"`
}
type Job struct {
	ID            string    `json:"id"`
	ProfileID     string    `json:"profile_id"`
	Status        string    `json:"status"`
	Error         string    `json:"error,omitempty"`
	CertificateID string    `json:"certificate_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Attempts      int       `json:"attempts"`
	RetryAt       time.Time `json:"retry_at"`
}

func (m *Manager) EnableChallenges()       { m.challengeEnabled = true }
func (m *Manager) ChallengesEnabled() bool { return m.challengeEnabled }
func validateProfile(r ProfileRequest) error {
	if !validTitle(r.Name) || !r.TOSAgreed || r.RenewBeforeDays < 1 || r.RenewBeforeDays > 60 {
		return errors.New("нужны название, согласие с условиями CA и окно продления 1–60 дней")
	}
	u, e := url.Parse(r.DirectoryURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("ACME directory должен быть HTTPS URL без пароля/fragment")
	}
	a, e := mail.ParseAddress(r.Email)
	if e != nil || a.Address != r.Email {
		return errors.New("нужен корректный email ACME-аккаунта")
	}
	if len(r.Domains) == 0 || len(r.Domains) > 32 {
		return errors.New("ACME: 1–32 DNS-имени")
	}
	for _, d := range r.Domains {
		if !validDNS(d, false) || strings.HasPrefix(d, "*.") || !strings.Contains(d, ".") {
			return errors.New("HTTP-01 требует обычные DNS-имена без wildcard")
		}
	}
	return nil
}
func (m *Manager) CreateProfile(r ProfileRequest) (Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := validateProfile(r); e != nil {
		return Profile{}, e
	}
	r.Domains = certs.NormalizeDomains(r.Domains)
	_, key, e := keyMaterial()
	if e != nil {
		return Profile{}, e
	}
	secret, e := m.encrypt(key)
	if e != nil {
		return Profile{}, e
	}
	p := Profile{ID: id(), ProfileRequest: r}
	body, _ := json.Marshal(p)
	tx, e := m.db.Begin()
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO acme_profiles(id,body,secret) VALUES(?,?,?)", p.ID, string(body), secret); e == nil {
		e = audit(tx, "pki.acme.profile.create", p.ID, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	return p, e
}
func (m *Manager) Profiles() ([]Profile, error) {
	rows, e := m.db.Query("SELECT body FROM acme_profiles ORDER BY rowid DESC")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var p Profile
		if e = json.Unmarshal([]byte(raw), &p); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (m *Manager) profile(id string) (Profile, []byte, error) {
	var p Profile
	var raw string
	var secret []byte
	e := m.db.QueryRow("SELECT body,secret FROM acme_profiles WHERE id=?", id).Scan(&raw, &secret)
	if e != nil {
		return p, nil, e
	}
	if e = json.Unmarshal([]byte(raw), &p); e != nil {
		return p, nil, e
	}
	key, e := m.decrypt(secret)
	return p, key, e
}
func (m *Manager) SetAutoRenew(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, _, e := m.profile(id)
	if e != nil {
		return e
	}
	p.AutoRenew = enabled
	body, _ := json.Marshal(p)
	tx, e := m.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE acme_profiles SET body=? WHERE id=?", string(body), id); e == nil {
		e = audit(tx, "pki.acme.auto_renew.change", id, m.now())
	}
	if e == nil {
		e = tx.Commit()
	}
	return e
}
func (m *Manager) Jobs() ([]Job, error) {
	rows, e := m.db.Query("SELECT body FROM acme_jobs ORDER BY rowid DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var j Job
		if e = json.Unmarshal([]byte(raw), &j); e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (m *Manager) Queue(profileID string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.challengeEnabled {
		return Job{}, errors.New("HTTP-01 выключен: настройте -acme-listen и доступ к TCP/80")
	}
	if _, _, e := m.profile(profileID); e != nil {
		return Job{}, e
	}
	var existing string
	e := m.db.QueryRow("SELECT body FROM acme_jobs WHERE profile_id=? AND json_extract(body,'$.status') IN ('queued','running') LIMIT 1", profileID).Scan(&existing)
	if e == nil {
		var j Job
		e = json.Unmarshal([]byte(existing), &j)
		return j, e
	}
	if e != sql.ErrNoRows {
		return Job{}, e
	}
	now := m.now().UTC()
	j := Job{ID: id(), ProfileID: profileID, Status: "queued", CreatedAt: now, UpdatedAt: now, RetryAt: now}
	body, _ := json.Marshal(j)
	tx, e := m.db.Begin()
	if e != nil {
		return j, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO acme_jobs(id,profile_id,body) VALUES(?,?,?)", j.ID, profileID, string(body)); e == nil {
		e = audit(tx, "pki.acme.issue.queue", profileID, now)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e == nil {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	return j, e
}

var challengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func (m *Manager) ChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		const prefix = "/.well-known/acme-challenge/"
		if !m.challengeEnabled || !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if !challengeToken.MatchString(token) {
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		var response string
		e := m.db.QueryRowContext(r.Context(), "SELECT response FROM acme_challenges WHERE token=? AND hostname=? AND expires>?", token, strings.ToLower(strings.TrimSuffix(host, ".")), m.now().UTC().Format(time.RFC3339Nano)).Scan(&response)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == "GET" {
			_, _ = io.WriteString(w, response)
		}
	})
}
func (m *Manager) saveJob(j Job) error {
	body, _ := json.Marshal(j)
	_, e := m.db.Exec("UPDATE acme_jobs SET body=? WHERE id=?", string(body), j.ID)
	return e
}
func (m *Manager) execute(ctx context.Context, j Job) {
	j.Status = "running"
	j.Attempts++
	j.UpdatedAt = m.now().UTC()
	if e := m.saveJob(j); e != nil {
		return
	}
	p, keyPEM, e := m.profile(j.ProfileID)
	var result acmeissue.Result
	if e == nil {
		var key *ecdsa.PrivateKey
		key, e = certs.ParseAccountKey(string(keyPEM))
		if e == nil {
			client := acmeissue.NewClient(key, p.DirectoryURL)
			client.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: secureTransport{doer: m.HTTPClient}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 5 || req.URL.Scheme != "https" {
					return errors.New("unsafe ACME redirect")
				}
				return nil
			}}
			if p.AccountURI != "" {
				client.KID = acme.KeyID(p.AccountURI)
			} else {
				var account *acme.Account
				account, e = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + p.Email}}, func(string) bool { return p.TOSAgreed })
				if e == nil {
					m.mu.Lock()
					latest, _, loadErr := m.profile(p.ID)
					if loadErr == nil {
						latest.AccountURI = account.URI
						raw, _ := json.Marshal(latest)
						_, loadErr = m.db.Exec("UPDATE acme_profiles SET body=? WHERE id=?", string(raw), p.ID)
					}
					m.mu.Unlock()
					e = loadErr
				}
			}
			if e == nil {
				result, e = acmeissue.IssueHTTP01(ctx, client, p.Domains, func(ctx context.Context, domain, token, response string, ttl time.Duration) error {
					if !challengeToken.MatchString(token) {
						return errors.New("invalid challenge token")
					}
					authorized := false
					for _, d := range p.Domains {
						if strings.EqualFold(d, strings.TrimSuffix(domain, ".")) {
							authorized = true
						}
					}
					if !authorized {
						return errors.New("CA requested an unexpected identifier")
					}
					_, e := m.db.ExecContext(ctx, "INSERT OR REPLACE INTO acme_challenges(token,hostname,response,expires) VALUES(?,?,?,?)", token, strings.ToLower(domain), response, m.now().Add(ttl).UTC().Format(time.RFC3339Nano))
					return e
				})
			}
		}
	}
	// Remove only this order's domain challenges; orders are serialized.
	_, _ = m.db.Exec("DELETE FROM acme_challenges")
	if e == nil {
		var pair *tls.Certificate
		pair, e = validatePair([]byte(result.CertPEM), []byte(result.KeyPEM), m.now())
		if e == nil && len(pair.Leaf.ExtKeyUsage) > 0 {
			allowed := false
			for _, usage := range pair.Leaf.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
					allowed = true
				}
			}
			if !allowed {
				e = errors.New("ACME certificate lacks serverAuth EKU")
			}
		}
		if e == nil && (len(pair.Leaf.DNSNames) != len(p.Domains) || len(pair.Leaf.IPAddresses) != 0) {
			e = errors.New("ACME returned an incompatible SAN set")
		}
		if e == nil {
			for _, name := range p.Domains {
				if e = pair.Leaf.VerifyHostname(name); e != nil {
					break
				}
			}
		}
	}
	m.mu.Lock()
	latest, _, loadErr := m.profile(j.ProfileID)
	if e == nil {
		e = loadErr
	}
	if e == nil {
		record, err := certificateEntry(p.Name, "acme", "", "server", []byte(result.CertPEM), []byte(result.KeyPEM), m.now())
		e = err
		if e == nil {
			record.ProfileID = p.ID
			tx, err := m.db.Begin()
			e = err
			if e == nil {
				defer tx.Rollback()
				e = m.insert(tx, record)
				if e == nil {
					latest.LatestID = record.ID
					latest.LastError = ""
					body, _ := json.Marshal(latest)
					_, e = tx.Exec("UPDATE acme_profiles SET body=? WHERE id=?", string(body), p.ID)
				}
				if e == nil {
					e = audit(tx, "pki.acme.issue.success", record.ID, m.now())
				}
				if e == nil {
					e = tx.Commit()
				}
				if e == nil {
					j.CertificateID = record.ID
				}
			}
		}
	}
	j.UpdatedAt = m.now().UTC()
	if e != nil {
		j.Error = e.Error()
		if len(j.Error) > 1000 {
			j.Error = j.Error[:1000]
		}
		j.Status = "failed"
		if j.Attempts >= 8 {
			latest.AutoRenew = false
		}
		if latest.AutoRenew && j.Attempts < 8 {
			j.Status = "queued"
			delay := time.Minute * time.Duration(1<<min(j.Attempts, 8))
			j.RetryAt = m.now().Add(delay).UTC()
		}
		latest.LastError = j.Error
		if loadErr == nil {
			body, _ := json.Marshal(latest)
			_, _ = m.db.Exec("UPDATE acme_profiles SET body=? WHERE id=?", string(body), latest.ID)
		}
	} else {
		j.Status = "issued"
		j.Error = ""
	}
	_ = m.saveJob(j)
	m.mu.Unlock()
}

type secureTransport struct{ doer HTTPDoer }

func (t secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, errors.New("ACME URL must use HTTPS")
	}
	if t.doer != nil {
		return t.doer.Do(r)
	}
	return http.DefaultTransport.RoundTrip(r)
}
func (m *Manager) RunACME(ctx context.Context) {
	// Running orders from a previous process must not remain stuck forever.
	jobs, _ := m.pendingJobs()
	for _, j := range jobs {
		if j.Status == "running" {
			j.Status = "queued"
			j.Error = "agent/controller restart interrupted order"
			j.RetryAt = m.now().Add(time.Minute)
			_ = m.saveJob(j)
		}
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if m.challengeEnabled {
			m.maintenance(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		}
	}
}
func (m *Manager) maintenance(ctx context.Context) {
	profiles, e := m.Profiles()
	if e != nil {
		return
	}
	for _, p := range profiles {
		if !p.AutoRenew {
			continue
		}
		due := p.LatestID == ""
		if p.LatestID != "" {
			x, e := m.get(p.LatestID)
			if e != nil {
				continue
			}
			window := min(time.Duration(p.RenewBeforeDays)*24*time.Hour, x.NotAfter.Sub(x.NotBefore)/3)
			due = !m.now().Before(x.NotAfter.Add(-window))
			m.deployRenewed(ctx, p)
		}
		if due {
			_, _ = m.Queue(p.ID)
		}
	}
	jobs, e := m.pendingJobs()
	if e != nil {
		return
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		if j.Status == "queued" && !m.now().Before(j.RetryAt) {
			jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			m.execute(jobCtx, j)
			cancel()
		}
	}
	for _, p := range profiles {
		if p.AutoRenew {
			fresh, _, e := m.profile(p.ID)
			if e == nil {
				m.deployRenewed(ctx, fresh)
			}
		}
	}
}
func (m *Manager) deployRenewed(ctx context.Context, p Profile) {
	s := m.TLSStatus()
	if !s.Enabled || s.PendingID != "" || s.ActiveID == "" || p.LatestID == "" || p.LatestID == s.ActiveID {
		return
	}
	active, e := m.get(s.ActiveID)
	if e != nil || active.ProfileID != p.ID {
		return
	}
	if _, e = m.SwitchTLS(ctx, p.LatestID, s.Hostname, 30); e == nil {
		e = m.ConfirmTLS(p.LatestID, s.Hostname)
	}
	if e != nil {
		m.mu.Lock()
		latest, _, err := m.profile(p.ID)
		if err == nil {
			latest.LastError = "TLS deployment: " + e.Error()
			body, _ := json.Marshal(latest)
			_, _ = m.db.Exec("UPDATE acme_profiles SET body=? WHERE id=?", string(body), p.ID)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) pendingJobs() ([]Job, error) {
	rows, e := m.db.Query("SELECT body FROM acme_jobs WHERE json_extract(body,'$.status') IN ('queued','running') ORDER BY rowid LIMIT 128")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var j Job
		if e = json.Unmarshal([]byte(raw), &j); e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
