package policy

import (
	"net/netip"
	"regexp"
)

type Snapshot struct {
	Version  int64            `json:"version"`
	Policies []CompiledPolicy `json:"policies"`
}

type CompiledPolicy struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Mode     string         `json:"mode"`
	Priority int            `json:"priority"`
	Rules    []CompiledRule `json:"rules"`
}

type CompiledRule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Action       string `json:"action"`
	Priority     int    `json:"priority"`
	PathExact    string `json:"path_exact,omitempty"`
	PathPrefix   string `json:"path_prefix,omitempty"`
	PathContains string `json:"path_contains,omitempty"`
	PathRegexRaw string `json:"path_regex,omitempty"`
	Method       string `json:"method,omitempty"`
	// ClientIPIn: if non-empty, rule matches only when client IP lies in any of these prefixes (allowlist semantics).
	ClientIPIn []netip.Prefix `json:"-"`
	// ClientIPNotIn: if non-empty, rule matches only when client IP lies in none of these (block external / IP denylist semantics).
	ClientIPNotIn      []netip.Prefix    `json:"-"`
	BodyContains       string            `json:"body_contains,omitempty"`
	RequestURIContains string            `json:"request_uri_contains,omitempty"`
	QueryEquals        map[string]string `json:"query_equals,omitempty"`
	HeaderContain      map[string]string `json:"header_contains,omitempty"`
	RedirectURL        string            `json:"redirect_url,omitempty"`
	ReplaceFrom        string            `json:"replace_from,omitempty"`
	ReplaceTo          string            `json:"replace_to,omitempty"`

	PathRegex *regexp.Regexp `json:"-"`
}
