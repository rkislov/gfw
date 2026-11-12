// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

// Package dnssec builds a local chain of trust. Upstream AD is never trusted.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	proof "github.com/semihalev/sdns/middleware/resolver/dnssec"
	"golang.org/x/sync/singleflight"
	"strings"
	"sync"
	"time"
)

type Fetch func(context.Context, string, uint16) (*dns.Msg, error)
type Result struct {
	Message *dns.Msg
	State   string
}
type Error struct {
	Code  uint16
	Cause error
}

func (e *Error) Error() string { return "DNSSEC: " + e.Cause.Error() }
func (e *Error) Unwrap() error { return e.Cause }
func bogus(err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	code := uint16(dns.ExtendedErrorCodeDNSBogus)
	switch {
	case errors.Is(err, proof.ErrInvalidSignaturePeriod):
		code = dns.ExtendedErrorCodeSignatureExpired
	case errors.Is(err, proof.ErrSignatureNotYetValid):
		code = dns.ExtendedErrorCodeSignatureNotYetValid
	case errors.Is(err, proof.ErrNoSignatures):
		code = dns.ExtendedErrorCodeRRSIGsMissing
	case errors.Is(err, proof.ErrMissingDNSKEY), errors.Is(err, proof.ErrNoDNSKEY):
		code = dns.ExtendedErrorCodeDNSKEYMissing
	case errors.Is(err, proof.ErrNSECMissingCoverage):
		code = dns.ExtendedErrorCodeNSECMissing
	}
	return &Error{code, err}
}

type zoneState struct {
	zone    string
	keys    map[uint16][]*dns.DNSKEY
	secure  bool
	expires time.Time
}
type Validator struct {
	config  Config
	anchors map[string][]dns.RR
	mu      sync.RWMutex
	cache   map[string]zoneState
	flights singleflight.Group
	crypto  *proof.CryptoLimiter
}

func New(c Config) (*Validator, error) {
	c, err := Normalize(c)
	if err != nil {
		return nil, err
	}
	v := &Validator{config: c, anchors: map[string][]dns.RR{}, cache: map[string]zoneState{}, crypto: proof.NewCryptoLimiter(32)}
	for _, line := range c.TrustAnchors {
		rr, _ := dns.NewRR(line)
		if key, ok := rr.(*dns.DNSKEY); ok {
			rr = key.ToDS(dns.SHA256)
		}
		v.anchors[rr.Header().Name] = append(v.anchors[rr.Header().Name], rr)
	}
	return v, nil
}

// NewWithRootAnchors overrides only the root. An empty managed set is intentional:
// it must never trigger Normalize's bootstrap defaults after a revocation.
func NewWithRootAnchors(c Config, roots []string) (*Validator, error) {
	v, err := New(c)
	if err != nil {
		return nil, err
	}
	delete(v.anchors, ".")
	for _, line := range roots {
		rr, err := dns.NewRR(line)
		if err != nil {
			return nil, err
		}
		if rr.Header().Name != "." {
			return nil, fmt.Errorf("managed anchor is not root")
		}
		if key, ok := rr.(*dns.DNSKEY); ok {
			rr = key.ToDS(dns.SHA256)
		}
		v.anchors["."] = append(v.anchors["."], rr)
	}
	return v, nil
}

type validationRun struct {
	v                                    *Validator
	ctx                                  context.Context
	fetch                                Fetch
	route                                string
	memo                                 map[string]zoneState
	queries, signatures, digests, hashes int
}

func (v *Validator) Validate(ctx context.Context, q, m *dns.Msg, route string, fetch Fetch) (Result, error) {
	if q == nil || m == nil || len(q.Question) != 1 || len(m.Question) != 1 {
		return Result{}, bogus(fmt.Errorf("invalid question"))
	}
	out := m.Copy()
	out.AuthenticatedData = false
	if out.Truncated || canonical(q.Question[0].Name) != canonical(out.Question[0].Name) || q.Question[0].Qtype != out.Question[0].Qtype || q.Question[0].Qclass != dns.ClassINET || out.Question[0].Qclass != dns.ClassINET {
		return Result{}, bogus(fmt.Errorf("invalid question"))
	}
	if out.Rcode != dns.RcodeSuccess && out.Rcode != dns.RcodeNameError {
		return Result{out, "indeterminate"}, nil
	}
	r := &validationRun{v: v, ctx: ctx, fetch: fetch, route: route, memo: map[string]zoneState{}}
	secure, err := r.answer(q.Question[0], out)
	if err != nil {
		return Result{}, bogus(err)
	}
	out.AuthenticatedData = secure
	state := "insecure"
	if secure {
		state = "secure"
	}
	return Result{out, state}, nil
}
func (r *validationRun) query(name string, typ uint16) (*dns.Msg, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	r.queries++
	if r.queries > 96 {
		return nil, fmt.Errorf("DNSSEC internal query budget exceeded")
	}
	m, err := r.fetch(r.ctx, name, typ)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Truncated || len(m.Question) != 1 || canonical(m.Question[0].Name) != canonical(name) || m.Question[0].Qtype != typ || m.Question[0].Qclass != dns.ClassINET {
		return nil, fmt.Errorf("invalid DNSSEC supporting response")
	}
	if err = r.preflight(m); err != nil {
		return nil, err
	}
	return m, nil
}
func (r *validationRun) preflight(m *dns.Msg) error {
	if len(m.Answer)+len(m.Ns) > 512 {
		return fmt.Errorf("DNSSEC response exceeds RR budget")
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range section {
			if rr.Header().Class != dns.ClassINET {
				return fmt.Errorf("non-IN DNSSEC record")
			}
			if n, ok := rr.(*dns.NSEC3); ok {
				if n.Hash != dns.SHA1 || n.Iterations > *r.v.config.MaxNSEC3Iterations {
					return fmt.Errorf("NSEC3 algorithm or iteration limit exceeded")
				}
			}
		}
	}
	return nil
}
func parent(n string) string {
	n = canonical(n)
	i := strings.IndexByte(n, '.')
	if i < 0 || i == len(n)-1 {
		return "."
	}
	return n[i+1:]
}
func (r *validationRun) state(name string, depth int) (zoneState, error) {
	name = canonical(name)
	if r.v.config.Exempt(name) {
		return zoneState{zone: name, expires: time.Now().Add(30 * time.Second)}, nil
	}
	if depth > 48 {
		return zoneState{}, fmt.Errorf("DNSSEC chain depth exceeded")
	}
	if s, ok := r.memo[name]; ok {
		return s, nil
	}
	key := r.route + "|" + name
	r.v.mu.RLock()
	s, ok := r.v.cache[key]
	r.v.mu.RUnlock()
	if ok && time.Now().Before(s.expires) {
		r.memo[name] = s
		return s, nil
	}
	value, err, _ := r.v.flights.Do(key, func() (any, error) {
		r.v.mu.RLock()
		s, ok := r.v.cache[key]
		r.v.mu.RUnlock()
		if ok && time.Now().Before(s.expires) {
			return s, nil
		}
		s, err := r.buildState(name, depth)
		if err != nil {
			return nil, err
		}
		if time.Now().Before(s.expires) {
			r.v.mu.Lock()
			if len(r.v.cache) >= 4096 {
				for k := range r.v.cache {
					delete(r.v.cache, k)
					break
				}
			}
			r.v.cache[key] = s
			r.v.mu.Unlock()
		}
		return s, nil
	})
	if err != nil {
		return zoneState{}, err
	}
	s = value.(zoneState)
	r.memo[name] = s
	return s, nil
}
func (r *validationRun) buildState(name string, depth int) (zoneState, error) {
	if anchors := r.v.anchors[name]; len(anchors) > 0 {
		return r.loadKeys(name, anchors, time.Now().Add(time.Hour))
	}
	if name == "." {
		return zoneState{}, fmt.Errorf("root trust anchor missing")
	}
	p, err := r.state(parent(name), depth+1)
	if err != nil {
		return zoneState{}, err
	}
	if !p.secure {
		return p, nil
	}
	m, err := r.query(name, dns.TypeDS)
	if err != nil {
		return zoneState{}, err
	}
	ds := rrset(m.Answer, name, dns.TypeDS)
	if len(ds) > 0 {
		proofMsg := message(m, ds, signatures(m.Answer, name, dns.TypeDS), nil)
		if err = r.verify(p, proofMsg); err != nil {
			return zoneState{}, err
		}
		expires := earlier(p.expires, expiry(proofMsg))
		supported := false
		for _, rr := range ds {
			supported = supported || proof.IsSupportedDS(rr.(*dns.DS))
		}
		if !supported {
			return zoneState{zone: name, expires: expires}, nil
		}
		return r.loadKeys(name, ds, expires)
	}
	// A signed alias proves that this owner is not a delegation. Its target's DS
	// is irrelevant to the source name, even if a recursive forwarder appends it.
	if aliases := rrset(m.Answer, name, dns.TypeCNAME); len(aliases) > 0 {
		records := append([]dns.RR{}, aliases...)
		for _, rr := range m.Answer {
			if d, ok := rr.(*dns.DNAME); ok && dns.IsSubDomain(canonical(d.Hdr.Name), name) {
				records = append(records, d)
			}
		}
		pm := scopedMessage(m, records, p.zone)
		if err = r.verify(p, pm); err != nil {
			return zoneState{}, err
		}
		wildcardSecure, err := proof.VerifyWildcardAnswerForZoneWithWork(pm, p.zone, r)
		if err != nil {
			return zoneState{}, err
		}
		p.secure = p.secure && wildcardSecure
		p.expires = earlier(p.expires, expiry(pm))
		return p, nil
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return zoneState{}, fmt.Errorf("DS lookup failed for %s", name)
	}
	pm := scopedMessage(m, nil, p.zone)
	if err = r.verify(p, pm); err != nil {
		return zoneState{}, err
	}
	nsec, nsec3 := denials(pm.Ns)
	if len(nsec)+len(nsec3) == 0 {
		return zoneState{}, proof.ErrNSECMissingCoverage
	}
	expires := earlier(p.expires, expiry(pm))
	if len(nsec) > 0 && proof.VerifyDelegationNSEC(name, nsec) == nil {
		return zoneState{zone: name, expires: expires}, nil
	}
	if len(nsec3) > 0 && proof.VerifyDelegationForZoneWithWork(name, p.zone, nsec3, r) == nil {
		return zoneState{zone: name, expires: expires}, nil
	}
	denialSecure, err := r.denial(pm, p.zone)
	if err != nil {
		return zoneState{}, err
	}
	p.secure = p.secure && denialSecure
	p.expires = expires
	return p, nil
}
func (r *validationRun) loadKeys(name string, ds []dns.RR, expires time.Time) (zoneState, error) {
	m, err := r.query(name, dns.TypeDNSKEY)
	if err != nil {
		return zoneState{}, err
	}
	keys := rrset(m.Answer, name, dns.TypeDNSKEY)
	if len(keys) == 0 || len(keys) > 64 {
		return zoneState{}, proof.ErrNoDNSKEY
	}
	all := map[uint16][]*dns.DNSKEY{}
	trusted := map[uint16][]*dns.DNSKEY{}
	for _, rr := range keys {
		key := rr.(*dns.DNSKEY)
		if key.Protocol != 3 || key.Flags&dns.ZONE == 0 || key.Flags&128 != 0 || !proof.IsSupportedDNSKEYAlgorithm(key.Algorithm) {
			continue
		}
		all[key.KeyTag()] = append(all[key.KeyTag()], key)
		// Only a DS-matched key may authenticate the initial DNSKEY RRset. A rogue
		// self-signed key appended beside the real KSK must never bootstrap trust.
		single := map[uint16][]*dns.DNSKEY{key.KeyTag(): {key}}
		unsupported, e := proof.VerifyDSWithWork(single, ds, r)
		if e == nil && !unsupported {
			trusted[key.KeyTag()] = append(trusted[key.KeyTag()], key)
		} else if proof.IsWorkError(e) {
			return zoneState{}, e
		}
	}
	if len(trusted) == 0 {
		return zoneState{}, proof.ErrMismatchingDS
	}
	pm := message(m, keys, signatures(m.Answer, name, dns.TypeDNSKEY), nil)
	state := zoneState{zone: name, keys: trusted, secure: true, expires: expires}
	if err = r.verify(state, pm); err != nil {
		return zoneState{}, err
	}
	state.keys = all
	state.expires = earlier(expires, expiry(pm))
	return state, nil
}
func (r *validationRun) verify(s zoneState, m *dns.Msg) error {
	if err := r.preflight(m); err != nil {
		return err
	}
	ok, err := proof.VerifyRRSIGWithWork(s.zone, s.keys, m, r)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("RRset signature was not authenticated")
	}
	return nil
}
func (r *validationRun) denial(m *dns.Msg, zone string) (bool, error) {
	nsec, nsec3 := denials(m.Ns)
	var err error = proof.ErrNSECMissingCoverage
	if len(nsec) > 0 {
		if m.Rcode == dns.RcodeNameError {
			err = proof.VerifyNameErrorNSEC(m, nsec)
		} else {
			err = proof.VerifyNODATANSEC(m, nsec)
		}
		if err == nil {
			return true, nil
		}
	}
	if len(nsec3) > 0 {
		if m.Rcode == dns.RcodeNameError {
			return proof.VerifyNameErrorForZoneWithWork(m, nsec3, zone, r)
		}
		return proof.VerifyNODATAForZoneWithWork(m, nsec3, zone, r)
	}
	return false, err
}
func (r *validationRun) CheckDNSKEYCandidate(used uint32) error {
	if used >= 8 {
		return fmt.Errorf("DNSSEC key-candidate limit exceeded")
	}
	return r.ctx.Err()
}
func (r *validationRun) CheckRRsetSignature(used uint32) error {
	if used >= 8 {
		return fmt.Errorf("DNSSEC RRset signature limit exceeded")
	}
	return r.ctx.Err()
}
func (r *validationRun) BeginSignature() (func(), error) {
	r.signatures++
	if r.signatures > 128 {
		return nil, fmt.Errorf("DNSSEC signature budget exceeded")
	}
	return r.v.crypto.Acquire(r.ctx)
}
func (r *validationRun) BeginDSDigest() (func(), error) {
	r.digests++
	if r.digests > 128 {
		return nil, fmt.Errorf("DNSSEC digest budget exceeded")
	}
	return r.v.crypto.Acquire(r.ctx)
}
func (r *validationRun) BeginNSEC3Hash() (func(), error) {
	r.hashes++
	if r.hashes > 256 {
		return nil, fmt.Errorf("DNSSEC NSEC3 work budget exceeded")
	}
	return r.v.crypto.Acquire(r.ctx)
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func expiry(m *dns.Msg) time.Time {
	now := time.Now()
	until := now.Add(time.Hour)
	for _, section := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range section {
			until = earlier(until, now.Add(time.Duration(rr.Header().Ttl)*time.Second))
			if sig, ok := rr.(*dns.RRSIG); ok {
				until = earlier(until, time.Unix(int64(sig.Expiration), 0))
				until = earlier(until, now.Add(time.Duration(sig.OrigTtl)*time.Second))
			}
			if soa, ok := rr.(*dns.SOA); ok {
				until = earlier(until, now.Add(time.Duration(soa.Minttl)*time.Second))
			}
		}
	}
	return until
}
func rrset(records []dns.RR, name string, typ uint16) []dns.RR {
	out := []dns.RR{}
	for _, rr := range records {
		if canonical(rr.Header().Name) == canonical(name) && rr.Header().Rrtype == typ {
			out = append(out, rr)
		}
	}
	return out
}
func signatures(records []dns.RR, name string, typ uint16) []dns.RR {
	out := []dns.RR{}
	for _, rr := range records {
		if s, ok := rr.(*dns.RRSIG); ok && canonical(s.Hdr.Name) == canonical(name) && s.TypeCovered == typ {
			out = append(out, s)
		}
	}
	return out
}
func message(original *dns.Msg, data, sigs, authority []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(original)
	m.Question = original.Question
	m.Rcode = original.Rcode
	m.Answer = append(append([]dns.RR{}, data...), sigs...)
	m.Ns = authority
	return m
}
func scopedMessage(original *dns.Msg, records []dns.RR, zone string) *dns.Msg {
	m := message(original, records, nil, nil)
	for _, rr := range records {
		m.Answer = append(m.Answer, signatures(original.Answer, rr.Header().Name, rr.Header().Rrtype)...)
	}
	for _, rr := range original.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeSOA:
			for _, s := range signatures(original.Ns, rr.Header().Name, rr.Header().Rrtype) {
				if canonical(s.(*dns.RRSIG).SignerName) == zone {
					m.Ns = append(m.Ns, rr)
					break
				}
			}
		case dns.TypeRRSIG:
			if canonical(rr.(*dns.RRSIG).SignerName) == zone {
				m.Ns = append(m.Ns, rr)
			}
		}
	}
	return m
}

func denials(records []dns.RR) (nsec, nsec3 []dns.RR) {
	for _, rr := range records {
		switch rr.(type) {
		case *dns.NSEC:
			nsec = append(nsec, rr)
		case *dns.NSEC3:
			nsec3 = append(nsec3, rr)
		}
	}
	return
}
