package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	URL          string `json:"url"`
	BaseDN       string `json:"base_dn"`
	Attribute    string `json:"attribute"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password,omitempty"`
	CA           string `json:"ca,omitempty"`
}

var attribute = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)

func (c LDAPConfig) validate() error {
	if c.URL == "" {
		if c.BaseDN != "" || c.BindDN != "" || c.BindPassword != "" || c.CA != "" {
			return errors.New("для LDAP нужен адрес LDAPS")
		}
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" ||
		len(c.URL) > 512 || len(c.BaseDN) > 2048 || len(c.BindDN) > 2048 || len(c.BindPassword) > 1024 || len(c.CA) > 65536 || !attribute.MatchString(c.Attribute) {
		return errors.New("нужен ldaps://сервер[:порт], Base DN и атрибут входа")
	}
	if c.BaseDN == "" {
		return errors.New("нужен Base DN")
	}
	if _, err = ldap.ParseDN(c.BaseDN); err != nil {
		return errors.New("некорректный Base DN")
	}
	if c.BindDN != "" {
		if _, err = ldap.ParseDN(c.BindDN); err != nil {
			return errors.New("некорректный Bind DN")
		}
		if c.BindPassword == "" {
			return errors.New("нужен пароль сервисной учётной записи LDAP")
		}
	} else if c.BindPassword != "" {
		return errors.New("укажите Bind DN")
	}
	if c.CA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CA)) {
		return errors.New("некорректный PEM CA")
	}
	return nil
}

func (s *Store) LDAP() (LDAPConfig, error) {
	var c LDAPConfig
	err := s.vault.Get("ldap", &c)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return c, err
}

func (s *Store) SaveLDAP(c LDAPConfig) error {
	old, err := s.LDAP()
	if err != nil {
		return err
	}
	if c.URL != "" && c.BindDN != "" && c.BindPassword == "" && c.URL == old.URL && c.BindDN == old.BindDN {
		c.BindPassword = old.BindPassword
	}
	if err = c.validate(); err != nil {
		return err
	}
	return s.vault.Put("ldap", c)
}

func (c LDAPConfig) bind(ctx context.Context, name, password string) error {
	if c.URL == "" || password == "" || !Username.MatchString(name) {
		return ErrDenied
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		port = "636"
	}
	settings := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.CA != "" {
		settings.RootCAs = x509.NewCertPool()
		if !settings.RootCAs.AppendCertsFromPEM([]byte(c.CA)) {
			return ErrDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: settings, NetDialer: &net.Dialer{Timeout: 4 * time.Second}}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return err
	}
	conn := ldap.NewConn(raw, true)
	conn.Start()
	defer conn.Close()
	if c.BindDN != "" {
		if err = conn.Bind(c.BindDN, c.BindPassword); err != nil {
			return err
		}
	}
	filter := "(" + c.Attribute + "=" + ldap.EscapeFilter(name) + ")"
	found, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 4, false, filter, []string{"1.1"}, nil))
	if err != nil {
		return err
	}
	if len(found.Entries) != 1 || strings.TrimSpace(found.Entries[0].DN) == "" {
		return ErrDenied
	}
	return conn.Bind(found.Entries[0].DN, password)
}
