// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net/url"
	"strings"
)

// AccessGroup grants one role for a VLAN scope. An empty scope is global.
type AccessGroup struct {
	Name    string `yaml:"name" json:"name"`
	Role    string `yaml:"role" json:"role"`
	VLANIDs []int  `yaml:"vlan_ids,omitempty" json:"vlan_ids,omitempty"`
	LDAPDN  string `yaml:"ldap_dn,omitempty" json:"ldap_dn,omitempty"`
}

type LDAP struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	URL            string `yaml:"url" json:"url"`
	StartTLS       bool   `yaml:"start_tls" json:"start_tls"`
	CAFile         string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	BindDN         string `yaml:"bind_dn" json:"bind_dn"`
	BindPassword   string `yaml:"bind_password,omitempty" json:"bind_password,omitempty"`
	BaseDN         string `yaml:"base_dn" json:"base_dn"`
	UserFilter     string `yaml:"user_filter" json:"user_filter"`
	GroupAttribute string `yaml:"group_attribute,omitempty" json:"group_attribute,omitempty"`
	TimeoutSeconds int    `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// ValidateLDAP refuses plaintext binds and malformed search filters.
func ValidateLDAP(c LDAP) error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return fmt.Errorf("LDAP URL must be ldaps://host:636 or ldap://host:389")
	}
	if u.Scheme == "ldap" && !c.StartTLS {
		return fmt.Errorf("LDAP requires LDAPS or StartTLS")
	}
	if u.Scheme == "ldaps" && c.StartTLS {
		return fmt.Errorf("StartTLS is only for ldap:// URLs")
	}
	if c.BindDN == "" || c.BindPassword == "" || c.BaseDN == "" {
		return fmt.Errorf("LDAP bind_dn, bind_password and base_dn are required")
	}
	if !strings.Contains(c.UserFilter, "{username}") {
		return fmt.Errorf("LDAP user_filter must contain {username}")
	}
	if _, err := ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, "{username}", "test")); err != nil {
		return fmt.Errorf("invalid LDAP user_filter: %w", err)
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 30 {
		return fmt.Errorf("LDAP timeout_seconds must be 0..30")
	}
	return nil
}

func validateGroupDN(dn string) error {
	if dn == "" {
		return nil
	}
	_, err := ldap.ParseDN(dn)
	return err
}
