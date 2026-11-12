// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	validation "github.com/rkislov/gfw/internal/engines/gdns/dnssec"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type runtimeState struct {
	snap    *snapshot
	cache   *cache
	flights singleflight.Group
}
type QueryLog struct {
	ID       uint64  `json:"id"`
	Time     string  `json:"time"`
	Client   string  `json:"client"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Result   string  `json:"result"`
	Duration float64 `json:"duration_ms"`
}
type Observer interface {
	ObserveDNS(string, string, time.Duration)
}
type observerSlot struct{ value Observer }
type Engine struct {
	updateMu     sync.Mutex
	manager      atomic.Pointer[validation.Manager]
	trustEpoch   atomic.Uint64
	trustBlocked atomic.Bool
	observer     atomic.Pointer[observerSlot]
	state        atomic.Pointer[runtimeState]
	Queries      atomic.Uint64
	Blocked      atomic.Uint64
	Hits         atomic.Uint64
	Failures     atomic.Uint64
	logMu        sync.RWMutex
	logs         []logSlot
	logLimit     int
	logSequence  atomic.Uint64
	logFloor     uint64
	slots        chan struct{}
}

func New(c Config) (*Engine, error) {
	e := &Engine{slots: make(chan struct{}, 256)}
	return e, e.Apply(c)
}
func (e *Engine) SetObserver(o Observer) { e.observer.Store(&observerSlot{o}) }
func (e *Engine) Apply(c Config) error   { return e.Update(c, nil) }

// Update prepares a new snapshot, persists it, then publishes it atomically.
// The persistence callback must not mutate the supplied configuration.
func (e *Engine) Update(c Config, persist func(Config) error) error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	c = cloneConfig(c)
	if old := e.state.Load(); old != nil {
		advancePrimarySerials(&c, old.snap.config)
	}
	s, err := compile(c)
	if err != nil {
		return err
	}
	if err := e.prepareManaged(s); err != nil {
		return err
	}
	if persist != nil {
		if err := persist(s.config); err != nil {
			return err
		}
	}
	e.state.Store(&runtimeState{snap: s, cache: newCache(c.CacheSize)})
	e.resizeLogs(s.config.QueryLogLimit)
	e.trustEpoch.Add(1)
	if m := e.manager.Load(); m != nil {
		m.Wake()
	}
	return nil
}
func (e *Engine) Config() Config { return cloneConfig(e.state.Load().snap.config) }
func (e *Engine) NeedsRestart(r Config) bool {
	c := e.state.Load().snap.config
	return c.UDPWorkers != r.UDPWorkers || c.DNSListen != r.DNSListen || c.HTTPListen != r.HTTPListen || c.DoHListen != r.DoHListen || c.DoTListen != r.DoTListen || c.TLSCertFile != r.TLSCertFile || c.TLSKeyFile != r.TLSKeyFile
}
func (e *Engine) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	transport := "tcp"
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		transport = "udp"
	}
	e.ServeDNSAs(w, q, transport)
}
func (e *Engine) ServeDNSAs(w dns.ResponseWriter, q *dns.Msg, transport string) {
	if len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeAXFR {
		e.serveAXFR(w, q)
		return
	}
	remote := w.RemoteAddr()
	ip := ClientIP(remote)
	r := e.AnswerAs(context.Background(), q, ip, transport)

	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		size := uint16(512)
		if opt := q.IsEdns0(); opt != nil {
			size = opt.UDPSize()
			if size < 512 {
				size = 512
			}
			if size > 1232 {
				size = 1232
			}
		}
		r.Truncate(int(size))
	}
	if t := q.IsTsig(); t != nil {
		if w.TsigStatus() != nil {
			_ = w.WriteMsg(newReply(q, dns.RcodeNotAuth))
			return
		}
		r.SetTsig(t.Hdr.Name, t.Algorithm, t.Fudge, time.Now().Unix())
	}
	_ = w.WriteMsg(r)
}

// Answer is the common entry point for UDP, TCP, DoH and DoT accounting and policy.
func (e *Engine) Answer(ctx context.Context, q *dns.Msg, ip netip.Addr) *dns.Msg {
	return e.AnswerAs(ctx, q, ip, "tcp")
}
func (e *Engine) AnswerAs(ctx context.Context, q *dns.Msg, ip netip.Addr, transport string) *dns.Msg {
	start := time.Now()
	e.Queries.Add(1)
	r, result := e.Resolve(ctx, q, ip.Unmap())
	end := time.Now()
	duration := end.Sub(start)
	if observer := e.observer.Load(); observer != nil && observer.value != nil {
		observer.value.ObserveDNS(transport, result, duration)
	}
	if len(q.Question) > 0 && e.state.Load().snap.config.QueryLog {
		e.appendLog(logEntry{at: end.UnixNano(), client: ip, name: q.Question[0].Name, qtype: q.Question[0].Qtype, result: result, duration: float64(duration.Microseconds()) / 1000})
	}
	return r
}

func (e *Engine) Resolve(ctx context.Context, q *dns.Msg, ip netip.Addr) (response *dns.Msg, result string) {
	epoch := e.trustEpoch.Load()
	defer func() {
		if epoch != e.trustEpoch.Load() || e.trustBlocked.Load() {
			response = new(dns.Msg)
			response.SetReply(q)
			response.Rcode = dns.RcodeServerFailure
			response.RecursionAvailable = true
			result = "SERVFAIL"
		}
	}()
	st := e.state.Load()
	s := st.snap
	if len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery {
		return newReply(q, dns.RcodeFormatError), "FORMERR"
	}
	allowed := false
	for _, p := range s.allowed {
		if p.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		return newReply(q, dns.RcodeRefused), "REFUSED"
	}
	question := q.Question[0]
	name := canonical(question.Name)
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		return newReply(q, dns.RcodeRefused), "REFUSED"
	}
	z := s.zone(name, ip)
	if z != nil && (z.Kind == "primary" || z.Kind == "secondary") {
		if z.Kind == "secondary" && !secondaryAvailable(z, time.Now()) {
			return newReply(q, dns.RcodeServerFailure), "SERVFAIL"
		}
		r := newReply(q, dns.RcodeSuccess)
		r.Authoritative = true
		// A delegation belongs to the parent; DS remains authoritative there.
		cut := ""
		for n := name; n != z.Name && withinZone(z.Name, n); {
			sets, _ := z.recordsFor(n, ip)
			if len(sets[dns.TypeNS]) > 0 {
				cut = n
			}
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
		}
		if cut != "" && !(name == cut && question.Qtype == dns.TypeDS) {
			r.Authoritative = false
			sets, _ := z.recordsFor(cut, ip)
			r.Ns = copyRRs(sets[dns.TypeNS], "")
			for _, rr := range r.Ns {
				ns := canonical(rr.(*dns.NS).Ns)
				if withinZone(cut, ns) {
					glue, _ := z.recordsFor(ns, ip)
					r.Extra = append(r.Extra, copyRRs(glue[dns.TypeA], "")...)
					r.Extra = append(r.Extra, copyRRs(glue[dns.TypeAAAA], "")...)
				}
			}
			return r, "DELEGATION"
		}

		records, exists := z.recordsFor(name, ip)
		if !exists && !z.nodeExists(name, ip) {
			// Wildcards only at the closest existing ancestor; empty non-terminals exist.
			ancestor := name
			for {
				i := strings.IndexByte(ancestor, '.')
				if i < 0 || i == len(ancestor)-1 {
					break
				}
				ancestor = ancestor[i+1:]
				if z.nodeExists(ancestor, ip) {
					records, exists = z.recordsFor("*."+ancestor, ip)
					break
				}
			}
		}
		if exists {
			if question.Qtype == dns.TypeANY {
				for _, set := range records {
					r.Answer = append(r.Answer, copyRRs(set, name)...)
				}
			} else {
				r.Answer = copyRRs(records[question.Qtype], name)
				if len(r.Answer) == 0 && question.Qtype != dns.TypeCNAME {
					r.Answer = copyRRs(records[dns.TypeCNAME], name)
				}
			}
		}
		if len(r.Answer) == 0 {
			if !exists && !z.nodeExists(name, ip) {
				r.Rcode = dns.RcodeNameError
			}
			r.Ns = copyRRs(z.soa, "")
			for _, rr := range r.Ns {
				soa := rr.(*dns.SOA)
				if soa.Minttl < soa.Hdr.Ttl {
					soa.Hdr.Ttl = soa.Minttl
				}
			}
		}
		return r, dns.RcodeToString[r.Rcode]
	}
	if s.isBlocked(name) {
		e.Blocked.Add(1)
		return newReply(q, dns.RcodeNameError), "BLOCKED"
	}
	if !q.RecursionDesired {
		return newReply(q, dns.RcodeRefused), "REFUSED"
	}
	do := q.IsEdns0() != nil && q.IsEdns0().Do()
	key := responseCacheKey(name, question.Qtype, do, q.CheckingDisabled, z)
	if cached := st.cache.getReply(key, q.IsEdns0() != nil); cached != nil {
		cached.Id = q.Id
		cached.Question = q.Question
		cached.Authoritative = false
		e.observeDNSSEC(s, cached, q, name)
		cached.RecursionAvailable = true
		cached.RecursionDesired = q.RecursionDesired
		cached.CheckingDisabled = q.CheckingDisabled
		e.Hits.Add(1)
		return clientResponse(cached, q), "CACHE"
	}
	value, err, _ := st.flights.Do(key, func() (any, error) {
		if cached := st.cache.getReply(key, q.IsEdns0() != nil); cached != nil {
			return cached, nil
		}

		timeout := 6 * time.Second
		if s.config.DNSSECValidation {
			timeout = time.Duration(s.config.DNSSEC.TimeoutSeconds) * time.Second
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		select {
		case e.slots <- struct{}{}:
			defer func() { <-e.slots }()
		default:
			return nil, fmt.Errorf("resolver busy")
		}
		request := new(dns.Msg)
		request.SetQuestion(name, question.Qtype)
		validate := s.validator != nil && !s.config.DNSSEC.Exempt(name) && (!q.CheckingDisabled || s.config.DNSSEC.IgnoreCD)
		request.CheckingDisabled = q.CheckingDisabled || validate
		request.SetEdns0(1232, do || validate)
		budget := 256
		answer, err := lookup(ctx, request, s, z, &budget)
		if err == nil {
			err = e.observeRootRevocation(ctx, answer)
		}
		if err == nil && answer != nil {
			answer.AuthenticatedData = false
		}
		if err == nil && validate {
			route := "global"
			if z != nil {
				route = "view/" + z.viewKey
			}
			result, e := s.validator.Validate(ctx, request, answer, route, func(ctx context.Context, n string, typ uint16) (*dns.Msg, error) {
				m := new(dns.Msg)
				m.SetQuestion(n, typ)
				m.CheckingDisabled = true
				m.SetEdns0(1232, true)
				answer, err := lookup(ctx, m, s, z, &budget)
				if err == nil {
					err = e.observeRootRevocation(ctx, answer)
				}
				return answer, err
			})
			err = e
			if err == nil {
				answer = result.Message
			}
		}

		if err != nil || answer == nil {
			return nil, err
		}
		// Blocked CNAME responses are not cached.
		blocked := false
		for _, rr := range answer.Answer {
			if c, ok := rr.(*dns.CNAME); ok && s.isBlocked(canonical(c.Target)) {
				blocked = true
			}
		}
		if !blocked {
			st.cache.put(key, answer)
		}
		return answer, nil
	})
	var answer *dns.Msg
	if value != nil {
		answer = value.(*dns.Msg).Copy()
	}

	if err != nil || answer == nil {
		r := newReply(q, dns.RcodeServerFailure)
		e.Failures.Add(1)
		var failure *validation.Error
		if errors.As(err, &failure) {
			e.observeDNSSECState("bogus")
			if q.IsEdns0() != nil {
				r.SetEdns0(1232, do)
				r.IsEdns0().Option = append(r.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: failure.Code, ExtraText: failure.Error()})
			}
			return r, "DNSSEC_BOGUS"
		}
		return r, "SERVFAIL"
	}

	for _, rr := range answer.Answer {
		if c, ok := rr.(*dns.CNAME); ok && s.isBlocked(canonical(c.Target)) {
			e.Blocked.Add(1)
			return newReply(q, dns.RcodeNameError), "BLOCKED"
		}
	}

	answer.Id = q.Id
	answer.Question = q.Question
	answer.RecursionDesired = q.RecursionDesired
	answer.RecursionAvailable = true
	answer.Authoritative = false
	e.observeDNSSEC(s, answer, q, name)
	answer.CheckingDisabled = q.CheckingDisabled
	if answer.Rcode == dns.RcodeServerFailure {
		e.Failures.Add(1)
	}
	return clientResponse(answer, q), dns.RcodeToString[answer.Rcode]
}
func responseCacheKey(name string, typ uint16, do, cd bool, z *compiledZone) string {
	if z == nil {
		return name + "/" + strconv.Itoa(int(typ)) + "/" + strconv.FormatBool(do) + "/" + strconv.FormatBool(cd)
	}
	return name + "/" + strconv.Itoa(int(typ)) + "/" + strconv.FormatBool(do) + "/" + strconv.FormatBool(cd) + "/view/" + z.viewKey
}

type replyWithQuestion struct {
	message  dns.Msg
	question [1]dns.Question
}

func newReply(q *dns.Msg, rcode int) *dns.Msg {
	allocation := new(replyWithQuestion)
	r := &allocation.message
	r.Id = q.Id
	r.Response = true
	r.Opcode = q.Opcode
	if q.Opcode == dns.OpcodeQuery {
		r.RecursionDesired = q.RecursionDesired
		r.CheckingDisabled = q.CheckingDisabled
	}
	if len(q.Question) > 0 {
		allocation.question[0] = q.Question[0]
		r.Question = allocation.question[:]
	}
	r.Rcode = rcode
	r.RecursionAvailable = true
	return r
}

func copyRRs(in []dns.RR, name string) []dns.RR {
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		r := dns.Copy(rr)
		if name != "" {
			r.Header().Name = name
		}
		out = append(out, r)
	}
	return out
}

var roots = []string{"198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53", "199.7.91.13:53", "192.203.230.10:53"} // IPv4 roots are sufficient for bootstrap.
func exchange(ctx context.Context, q *dns.Msg, servers []string, budget *int) (*dns.Msg, error) {
	var last error
	for _, server := range servers {
		if *budget <= 0 {
			return nil, fmt.Errorf("exchange budget exceeded")
		}
		*budget--
		c := &dns.Client{Net: "udp", Timeout: 800 * time.Millisecond}
		m, _, err := c.ExchangeContext(ctx, q, server)
		if err == nil && m.Truncated {
			c.Net = "tcp"
			m, _, err = c.ExchangeContext(ctx, q, server)
		}
		if err == nil && (!m.Response || m.Opcode != q.Opcode || len(m.Question) != 1 || canonical(m.Question[0].Name) != canonical(q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass) {
			err = fmt.Errorf("upstream response question mismatch")
		}
		if err == nil && m.Rcode != dns.RcodeServerFailure && m.Rcode != dns.RcodeRefused {
			return m, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("no DNS server answered: %v", last)
}
func iterate(ctx context.Context, q *dns.Msg, servers []string, cut string, depth int, budget *int) (*dns.Msg, error) {
	if depth > 12 {
		return nil, fmt.Errorf("recursive dependency limit")
	}
	q = q.Copy()
	q.RecursionDesired = false
	for hop := 0; hop < 32; hop++ {
		m, err := exchange(ctx, q, servers, budget)
		if err != nil {
			return nil, err
		}
		if len(m.Answer) > 0 {
			if !m.Authoritative {
				return nil, fmt.Errorf("non-authoritative final answer")
			}
			// Complete CNAME chains even when the authoritative server only returns aliases.
			target := ""
			hasType := false
			for _, rr := range m.Answer {
				if rr.Header().Rrtype == q.Question[0].Qtype {
					hasType = true
				}
				if c, ok := rr.(*dns.CNAME); ok {
					target = c.Target
				}
			}
			if !hasType && target != "" && q.Question[0].Qtype != dns.TypeCNAME {
				next := q.Copy()
				next.SetQuestion(target, q.Question[0].Qtype)
				tail, e := iterate(ctx, next, roots, ".", depth+1, budget)
				if e != nil {
					return nil, e
				}
				m.Answer = append(m.Answer, tail.Answer...)
				m.Ns = append(m.Ns, tail.Ns...)
				m.Rcode = tail.Rcode
			}
			return m, nil
		}
		if m.Authoritative && (m.Rcode == dns.RcodeNameError || hasSOA(m.Ns)) {
			return m, nil
		}
		delegation := ""
		var names []string
		for _, rr := range m.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				owner := canonical(ns.Hdr.Name)
				if withinZone(cut, owner) && owner != cut && withinZone(owner, q.Question[0].Name) {
					if delegation == "" || len(owner) > len(delegation) {
						delegation = owner
						names = nil
					}
					if owner == delegation {
						names = append(names, canonical(ns.Ns))
					}
				}
			}
		}
		if delegation == "" {
			return nil, fmt.Errorf("invalid delegation")
		}
		nextServers := glueServers(m.Extra, names, cut)
		if len(nextServers) == 0 {
			for _, ns := range names {
				nq := new(dns.Msg)
				nq.SetQuestion(ns, dns.TypeA)
				nq.SetEdns0(1232, false)
				a, e := iterate(ctx, nq, roots, ".", depth+1, budget)
				if e == nil {
					for _, rr := range a.Answer {
						if ar, ok := rr.(*dns.A); ok {
							nextServers = append(nextServers, net.JoinHostPort(ar.A.String(), "53"))
						}
					}
				}
				if len(nextServers) > 0 {
					break
				}
			}
		}
		if len(nextServers) == 0 {
			return nil, fmt.Errorf("delegation has no reachable servers")
		}
		servers = nextServers
		cut = delegation
	}
	return nil, fmt.Errorf("delegation limit")
}
func hasSOA(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// Glue must match a delegated nameserver and lie within the responding parent zone.
// Root referrals commonly carry sibling glue (e.g. com -> gtld-servers.net).
func glueServers(records []dns.RR, names []string, cut string) []string {
	nextServers := []string{}
	for _, ns := range names {
		if !withinZone(cut, ns) {
			continue
		}
		for _, rr := range records {
			if canonical(rr.Header().Name) != ns {
				continue
			}
			switch a := rr.(type) {
			case *dns.A:
				nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
			case *dns.AAAA:
				nextServers = append(nextServers, net.JoinHostPort(a.AAAA.String(), "53"))
			}
		}
	}
	return nextServers
}

func lookup(ctx context.Context, q *dns.Msg, s *snapshot, z *compiledZone, budget *int) (*dns.Msg, error) {
	if z != nil && z.Kind == "forward" {
		q.RecursionDesired = true
		return exchange(ctx, q, z.Servers, budget)
	}
	if z != nil && z.Kind == "stub" && withinZone(z.Name, q.Question[0].Name) && !(q.Question[0].Qtype == dns.TypeDS && canonical(q.Question[0].Name) == z.Name) {
		return iterate(ctx, q, z.Servers, z.Name, 0, budget)
	}
	if s.config.Mode == "forward" {
		q.RecursionDesired = true
		return exchange(ctx, q, s.config.Upstreams, budget)
	}
	return iterate(ctx, q, roots, ".", 0, budget)
}
func clientResponse(m, q *dns.Msg) *dns.Msg {
	do := q.IsEdns0() != nil && q.IsEdns0().Do()
	m.AuthenticatedData = m.AuthenticatedData && !q.CheckingDisabled && (do || q.AuthenticatedData)
	m.CheckingDisabled = q.CheckingDisabled
	if !do {
		filter := func(records []dns.RR) []dns.RR {
			out := records[:0]
			for _, rr := range records {
				switch rr.Header().Rrtype {
				case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeDS:
					if rr.Header().Rrtype != q.Question[0].Qtype {
						continue
					}
				}
				out = append(out, rr)
			}
			return out
		}
		m.Answer = filter(m.Answer)
		m.Ns = filter(m.Ns)
	}
	// Reuse only a private, single OPT (including the coallocated cache reply).
	// Reinitialize the whole record so upstream cookies/ECS/options never leak.
	if q.IsEdns0() != nil {
		var opt *dns.OPT
		if len(m.Extra) == 1 {
			opt, _ = m.Extra[0].(*dns.OPT)
		}
		if opt == nil {
			m.Extra = nil
			m.SetEdns0(1232, do)
		} else {
			*opt = dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}
			if do {
				opt.SetDo()
			}
		}
	} else {
		m.Extra = nil
	}
	return m
}
func (e *Engine) observeDNSSECState(state string) {
	if slot := e.observer.Load(); slot != nil && slot.value != nil {
		if observer, ok := slot.value.(interface{ ObserveDNSSEC(string) }); ok {
			observer.ObserveDNSSEC(state)
		}
	}
}
func (e *Engine) observeDNSSEC(s *snapshot, m, q *dns.Msg, name string) {
	state := "insecure"
	switch {
	case !s.config.DNSSECValidation:
		state = "disabled"
	case s.config.DNSSEC.Exempt(name):
		state = "exempt"
	case q.CheckingDisabled && !s.config.DNSSEC.IgnoreCD:
		state = "bypass"
	case m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError:
		state = "indeterminate"
	case len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeRRSIG:
		state = "indeterminate"
	case m.AuthenticatedData:
		state = "secure"
	}
	e.observeDNSSECState(state)
}

func (e *Engine) DNSSECStatus() map[string]any {
	c := e.state.Load().snap.config
	state := "disabled"
	if c.DNSSECValidation {
		state = "validating"
	}
	status := map[string]any{"enabled": c.DNSSECValidation, "state": state, "trust_anchor_count": len(c.DNSSEC.TrustAnchors), "exempt_zones": append([]string{}, c.DNSSEC.ExemptZones...), "honor_cd": !c.DNSSEC.IgnoreCD}
	if m := e.manager.Load(); m != nil {
		status["rfc5011"] = m.Status(c.DNSSEC)
	}
	return status
}

func (e *Engine) prepareManaged(s *snapshot) error {
	m := e.manager.Load()
	if m == nil {
		return nil
	}
	if err := m.CheckSeeds(s.config.DNSSEC); err != nil {
		return err
	}
	if roots, initialized := m.Roots(); initialized && s.config.DNSSECValidation {
		v, err := validation.NewWithRootAnchors(s.config.DNSSEC, roots)
		if err != nil {
			return err
		}
		s.validator = v
	}
	return nil
}
func (e *Engine) SetRootManager(m *validation.Manager) error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	e.manager.Store(m)
	m.SetRevocationBarrier(func() { e.trustBlocked.Store(true); e.trustEpoch.Add(1) })
	s, err := compile(e.state.Load().snap.config)
	if err != nil {
		return err
	}
	if err = e.prepareManaged(s); err != nil {
		return err
	}
	e.state.Store(&runtimeState{snap: s, cache: newCache(s.config.CacheSize)})
	e.trustEpoch.Add(1)
	return nil
}
func (e *Engine) RefreshRootAnchors(ctx context.Context) error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	m := e.manager.Load()
	if m == nil {
		return fmt.Errorf("RFC 5011 state store is unavailable")
	}
	s := e.state.Load().snap
	before, initializedBefore := m.Roots()
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.DNSSEC.TimeoutSeconds)*time.Second)
	defer cancel()
	err := m.Refresh(probeCtx, s.config.DNSSEC, func(ctx context.Context, name string, typ uint16) (*dns.Msg, error) {
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		q.CheckingDisabled = true
		q.SetEdns0(1232, true)
		budget := 64
		return lookup(ctx, q, s, nil, &budget)
	})
	after, initializedAfter := m.Roots()
	if initializedBefore != initializedAfter || strings.Join(before, "\n") != strings.Join(after, "\n") {
		next, compileErr := compile(s.config)
		if compileErr != nil {
			return compileErr
		}
		if compileErr = e.prepareManaged(next); compileErr != nil {
			return compileErr
		}
		e.state.Store(&runtimeState{snap: next, cache: newCache(next.config.CacheSize)})
		e.trustEpoch.Add(1)
	}
	e.trustBlocked.Store(false)
	return err
}

func (e *Engine) observeRootRevocation(ctx context.Context, msg *dns.Msg) error {
	m := e.manager.Load()
	if m == nil || !m.NeedsRevocation(msg) {
		return nil
	}
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if !m.NeedsRevocation(msg) {
		return nil
	}
	before, _ := m.Roots()
	s := e.state.Load().snap
	err := m.ObserveRevocation(ctx, s.config.DNSSEC, msg)
	after, _ := m.Roots()
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		next, compileErr := compile(s.config)
		if compileErr != nil {
			return compileErr
		}
		if compileErr = e.prepareManaged(next); compileErr != nil {
			return compileErr
		}
		e.state.Store(&runtimeState{snap: next, cache: newCache(next.config.CacheSize)})
		e.trustEpoch.Add(1)
	}
	e.trustBlocked.Store(false)
	return err
}

func (e *Engine) RootTrustStatus() validation.ManagedStatus {
	if m := e.manager.Load(); m != nil {
		return m.Status(e.state.Load().snap.config.DNSSEC)
	}
	return validation.ManagedStatus{State: "unavailable"}
}
