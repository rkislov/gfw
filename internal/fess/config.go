package fess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rkislov/gfw/internal/engines/fess/policy"
)

type Config struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	TLS     bool   `json:"tls"`
	Sites   []Site `json:"sites"`
}

type Site struct {
	Host        string `json:"host"`
	Path        string `json:"path"`
	Upstream    string `json:"upstream"`
	Certificate string `json:"certificate"`
	Mode        string `json:"mode"`
	Rules       []Rule `json:"rules"`
	Pack        *Pack  `json:"pack,omitempty"`
	UsePack     bool   `json:"use_pack"`
}

type Pack struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Action    string          `json:"action"`
	Priority  int             `json:"priority"`
	Condition json.RawMessage `json:"condition"`
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var ruleID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hostName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}

func port(address string) string {
	_, p, _ := net.SplitHostPort(address)
	return p
}

func Validate(c Config, reserved ...string) error {
	if len(c.Sites) > 32 || (c.Enabled && (c.Listen == "" || len(c.Sites) == 0)) {
		return errors.New("Укажите адрес прослушивания и от одного до 32 сайтов")
	}
	if c.Listen != "" {
		host, p, err := net.SplitHostPort(c.Listen)
		n, parseErr := strconv.Atoi(p)
		addr, addrErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || addrErr != nil || addr.Zone() != "" || addr.IsMulticast() || n < 1 || n > 65535 || p != strconv.Itoa(n) {
			return errors.New("Адрес прослушивания должен содержать IP и TCP-порт")
		}
		for _, address := range reserved {
			if port(address) == p {
				return errors.New("Порт зарезервирован для панели или ACME")
			}
		}
	}
	routes := map[string]bool{}
	certs := map[string]string{}
	for _, s := range c.Sites {
		if !hostName(s.Host) || !strings.HasPrefix(s.Path, "/") || strings.ContainsAny(s.Path, "?#% \\") ||
			len(s.Path) > 250 || (s.Path != "/" && strings.HasSuffix(s.Path, "/")) {
			return errors.New("Укажите домен в нижнем регистре и префикс пути, например /api")
		}
		key := s.Host + s.Path
		if routes[key] {
			return fmt.Errorf("Повтор маршрута %s", key)
		}
		routes[key] = true
		if c.TLS && (s.Certificate == "" || certs[s.Host] != "" && certs[s.Host] != s.Certificate) {
			return fmt.Errorf("Для %s нужен один сертификат на все маршруты", s.Host)
		}
		certs[s.Host] = s.Certificate
		u, err := url.Parse(s.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s.Upstream) > 512 ||
			u.Path != "" && u.Path != "/" {
			return fmt.Errorf("Укажите HTTP(S) адрес upstream без пути и учётных данных для %s", key)
		}
		if s.Mode != "log" && s.Mode != "block" {
			return errors.New("Укажите режим WAF log или block")
		}
		if s.UsePack && s.Pack == nil {
			return errors.New("Сначала загрузите набор WAF")
		}
		if s.Pack != nil && (!ruleID.MatchString(s.Pack.ID) || !ruleID.MatchString(s.Pack.Version) || !hash.MatchString(s.Pack.SHA256)) {
			return errors.New("Некорректное происхождение набора WAF")
		}
		if _, _, err := compileRules(s); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func compileRules(s Site) ([]policy.CompiledRule, bool, error) {
	rules := slices.Clone(s.Rules)
	if s.Pack != nil {
		rules = append(rules, s.Pack.Rules...)
	}
	if len(rules) > 512 {
		return nil, false, errors.New("Допустимо до 512 правил на маршрут")
	}
	seen := map[string]bool{}
	var out []policy.CompiledRule
	body := false
	for i, r := range rules {
		if !ruleID.MatchString(r.ID) || seen[r.ID] || len(r.Name) == 0 || len(r.Name) > 240 ||
			(r.Action != "block" && r.Action != "log") {
			return nil, false, fmt.Errorf("Некорректное правило %q", r.ID)
		}
		seen[r.ID] = true
		var c policy.CompiledRule
		dec := json.NewDecoder(bytes.NewReader(r.Condition))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil || dec.Decode(new(any)) != io.EOF {
			return nil, false, fmt.Errorf("Неподдерживаемое условие в правиле %s", r.ID)
		}
		if c.ID != "" || c.Name != "" || c.Action != "" || c.Priority != 0 || c.RedirectURL != "" || c.ReplaceFrom != "" || c.ReplaceTo != "" ||
			(c.PathExact == "" && c.PathPrefix == "" && c.PathContains == "" && c.PathRegexRaw == "" && c.Method == "" &&
				c.BodyContains == "" && c.RequestURIContains == "" && len(c.QueryEquals) == 0 && len(c.HeaderContain) == 0) {
			return nil, false, fmt.Errorf("Правилу %s требуется условие запроса", r.ID)
		}
		if c.PathRegexRaw != "" {
			re, err := regexp.Compile(c.PathRegexRaw)
			if err != nil {
				return nil, false, fmt.Errorf("Некорректное регулярное выражение правила %s", r.ID)
			}
			c.PathRegex = re
		}
		if i < len(s.Rules) || s.UsePack {
			c.ID, c.Name, c.Action, c.Priority = r.ID, r.Name, r.Action, r.Priority
			out = append(out, c)
			body = body || c.BodyContains != ""
		}
	}
	slices.SortStableFunc(out, func(a, b policy.CompiledRule) int {
		if a.Priority < b.Priority {
			return -1
		}
		if a.Priority > b.Priority {
			return 1
		}
		return 0
	})
	return out, body, nil
}
