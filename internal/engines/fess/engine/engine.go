package engine

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/rkislov/gfw/internal/engines/fess/policy"
)

type Decision struct {
	Action      string
	PolicyID    string
	PolicyMode  string
	RuleID      string
	Reason      string
	RedirectURL string
}

type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// Evaluate runs the WAF rule chain. clientHost is the resolved client IP string (no port), same as used in logs.
func (e *Evaluator) Evaluate(r *http.Request, snapshot policy.Snapshot, sitePolicyID, clientHost string) Decision {
	return e.EvaluateBody(r, snapshot, sitePolicyID, clientHost, readBodySafely(r))
}

// EvaluateBody evaluates an already buffered request without reading or replacing r.Body.
func (e *Evaluator) EvaluateBody(r *http.Request, snapshot policy.Snapshot, sitePolicyID, clientHost string, body []byte) Decision {
	path := r.URL.Path
	query := r.URL.Query()

	uri := r.URL.RequestURI()

	for _, p := range snapshot.Policies {
		if sitePolicyID != "" && p.ID != sitePolicyID {
			continue
		}
		for _, rule := range p.Rules {
			if !clientIPMatchesRule(rule, clientHost) {
				continue
			}
			if rule.Method != "" && !strings.EqualFold(rule.Method, r.Method) {
				continue
			}
			if rule.RequestURIContains != "" && !strings.Contains(uri, rule.RequestURIContains) {
				continue
			}
			if rule.PathExact != "" && rule.PathExact != path {
				continue
			}
			if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
				continue
			}
			if rule.PathContains != "" && !strings.Contains(path, rule.PathContains) {
				continue
			}
			if rule.PathRegex != nil && !rule.PathRegex.MatchString(path) {
				continue
			}
			if rule.BodyContains != "" && !bytes.Contains(body, []byte(rule.BodyContains)) {
				continue
			}
			if !matchQuery(rule.QueryEquals, query) {
				continue
			}
			if !matchHeaders(rule.HeaderContain, r.Header) {
				continue
			}
			return Decision{
				Action:      rule.Action,
				PolicyID:    p.ID,
				PolicyMode:  p.Mode,
				RuleID:      rule.ID,
				Reason:      rule.Name,
				RedirectURL: rule.RedirectURL,
			}
		}
	}
	return Decision{Action: "allow", Reason: "default allow"}
}

func readBodySafely(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

func matchQuery(expect map[string]string, actual map[string][]string) bool {
	for k, v := range expect {
		got, ok := actual[k]
		if !ok || len(got) == 0 || got[0] != v {
			return false
		}
	}
	return true
}

func matchHeaders(expect map[string]string, actual http.Header) bool {
	for k, v := range expect {
		got := actual.Get(k)
		if got == "" || !strings.Contains(strings.ToLower(got), strings.ToLower(v)) {
			return false
		}
	}
	return true
}

func parseEffectiveClient(host string) (netip.Addr, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if !a.IsValid() {
		return netip.Addr{}, false
	}
	return a, true
}

func prefixListContains(list []netip.Prefix, addr netip.Addr) bool {
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func clientIPMatchesRule(rule policy.CompiledRule, clientHost string) bool {
	hasConstraint := len(rule.ClientIPIn) > 0 || len(rule.ClientIPNotIn) > 0
	addr, ok := parseEffectiveClient(clientHost)
	if hasConstraint && !ok {
		return false
	}
	if len(rule.ClientIPIn) > 0 {
		if !prefixListContains(rule.ClientIPIn, addr) {
			return false
		}
	}
	if len(rule.ClientIPNotIn) > 0 && prefixListContains(rule.ClientIPNotIn, addr) {
		return false
	}
	return true
}
