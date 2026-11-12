// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
	proof "github.com/semihalev/sdns/middleware/resolver/dnssec"
	"strings"
	"time"
)

// answer validates only the RRsets on the actual CNAME/DNAME resolution path.
// Unrelated answer and additional data are removed rather than laundered under AD.
func (r *validationRun) answer(question dns.Question, m *dns.Msg) (bool, error) {
	if err := r.preflight(m); err != nil {
		return false, err
	}
	original := m.Copy()
	name := canonical(question.Name)
	secure := true
	seen := map[string]bool{}
	kept := []dns.RR{}
	authority := []dns.RR{}
	expiryLimit := time.Now().Add(time.Hour)
	finalize := func() bool { m.Ns = authority; return r.finish(m, original, secure, expiryLimit) }
	keep := func(records []dns.RR) {
		kept = append(kept, records...)
		for _, rr := range records {
			kept = append(kept, signatures(original.Answer, rr.Header().Name, rr.Header().Rrtype)...)
		}
	}
	// Explicit RRSIG queries carry signatures, not a signed RRset of RRSIGs.
	// They cannot be declared authenticated solely from the returned bytes.
	if question.Qtype == dns.TypeRRSIG {
		m.AuthenticatedData = false
		m.Extra = nil
		return false, nil
	}
	for depth := 0; depth < 16; depth++ {
		if seen[name] {
			return false, fmt.Errorf("DNSSEC alias loop")
		}
		seen[name] = true
		cname := rrset(original.Answer, name, dns.TypeCNAME)
		var dname *dns.DNAME
		for _, rr := range original.Answer {
			if d, ok := rr.(*dns.DNAME); ok && canonical(d.Hdr.Name) != name && dns.IsSubDomain(canonical(d.Hdr.Name), name) {
				if dname == nil || dns.CountLabel(d.Hdr.Name) > dns.CountLabel(dname.Hdr.Name) {
					dname = d
				}
			}
		}
		if dname != nil {
			owner := canonical(dname.Hdr.Name)
			target := strings.TrimSuffix(name, owner) + canonical(dname.Target)
			if _, ok := dns.IsDomainName(target); !ok || len(target) > 255 {
				return false, fmt.Errorf("DNAME synthesis exceeds DNS name size")
			}
			if len(cname) != 1 || canonical(cname[0].(*dns.CNAME).Target) != target {
				return false, fmt.Errorf("invalid unsigned DNAME synthesis")
			}
			records := []dns.RR{dname, cname[0]}
			s, err := r.state(owner, 0)
			if err != nil {
				return false, err
			}
			pm := scopedMessage(original, records, s.zone)
			if s.secure {
				if err = r.verify(s, pm); err != nil {
					return false, err
				}
				authority = append(authority, pm.Ns...)
				ok, e := proof.VerifyWildcardAnswerForZoneWithWork(pm, s.zone, r)
				if e != nil {
					return false, e
				}
				secure = secure && ok
			} else {
				secure = false
			}
			expiryLimit = earlier(expiryLimit, s.expires)
			keep(records)
			name = target
			continue
		}
		if len(cname) > 0 {
			if len(cname) != 1 {
				return false, fmt.Errorf("multiple CNAME targets")
			}
			s, err := r.state(name, 0)
			if err != nil {
				return false, err
			}
			pm := scopedMessage(original, cname, s.zone)
			if s.secure {
				if err = r.verify(s, pm); err != nil {
					return false, err
				}
				authority = append(authority, pm.Ns...)
				ok, e := proof.VerifyWildcardAnswerForZoneWithWork(pm, s.zone, r)
				if e != nil {
					return false, e
				}
				secure = secure && ok
			} else {
				secure = false
			}
			expiryLimit = earlier(expiryLimit, s.expires)
			keep(cname)
			if question.Qtype == dns.TypeCNAME {
				m.Answer = kept
				return finalize(), nil
			}
			name = canonical(cname[0].(*dns.CNAME).Target)
			continue
		}
		records := rrset(original.Answer, name, question.Qtype)
		if question.Qtype == dns.TypeANY {
			records = nil
			for _, rr := range original.Answer {
				if canonical(rr.Header().Name) == name && rr.Header().Rrtype != dns.TypeRRSIG {
					records = append(records, rr)
				}
			}
		}
		stateName := name
		if question.Qtype == dns.TypeDS && name != "." {
			stateName = parent(name)
		}
		s, err := r.state(stateName, 0)
		if err != nil {
			return false, err
		}
		expiryLimit = earlier(expiryLimit, s.expires)
		if len(records) > 0 {
			if original.Rcode != dns.RcodeSuccess {
				return false, fmt.Errorf("positive RRset contradicts NXDOMAIN")
			}
			pm := scopedMessage(original, records, s.zone)
			if s.secure {
				if err = r.verify(s, pm); err != nil {
					return false, err
				}
				authority = append(authority, pm.Ns...)
				ok, e := proof.VerifyWildcardAnswerForZoneWithWork(pm, s.zone, r)
				if e != nil {
					return false, e
				}
				secure = secure && ok
			} else {
				secure = false
			}
			keep(records)
			m.Answer = kept
			return finalize(), nil
		}
		// A signed NXDOMAIN/NODATA proof must be evaluated at the final alias target,
		// with its exact signer and original query type, never at the initial alias.
		pm := scopedMessage(original, nil, s.zone)
		pm.Question = []dns.Question{{Name: name, Qtype: question.Qtype, Qclass: question.Qclass}}
		if s.secure {
			if !hasSOAFor(pm.Ns, s.zone) {
				return false, fmt.Errorf("signed negative answer is missing zone SOA")
			}
			if err = r.verify(s, pm); err != nil {
				return false, err
			}
			authority = append(authority, pm.Ns...)
			ok, e := r.denial(pm, s.zone)
			if e != nil {
				return false, e
			}
			secure = secure && ok
		} else {
			secure = false
		}
		m.Answer = kept
		return finalize(), nil
	}
	return false, fmt.Errorf("DNSSEC alias depth exceeded")
}
func hasSOAFor(records []dns.RR, zone string) bool {
	for _, rr := range records {
		if _, ok := rr.(*dns.SOA); ok && canonical(rr.Header().Name) == zone {
			return true
		}
	}
	return false
}
func (r *validationRun) finish(m, original *dns.Msg, secure bool, until time.Time) bool {
	// Retain only the authority records that were authenticated on the actual
	// resolution path. The original Additional section is never trusted.
	deduplicate := func(records []dns.RR) []dns.RR {
		out := []dns.RR{}
		seen := map[string]bool{}
		for _, rr := range records {
			key := rr.String()
			if !seen[key] {
				seen[key] = true
				out = append(out, rr)
			}
		}
		return out
	}
	m.Answer = deduplicate(m.Answer)
	m.Ns = deduplicate(m.Ns)

	if !secure && len(m.Ns) == 0 {
		for _, rr := range original.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				m.Ns = append(m.Ns, dns.Copy(rr))
			}
		}
	}
	m.Extra = nil
	until = earlier(until, expiry(m))
	ttl := uint32(0)
	if delta := time.Until(until); delta > 0 {
		ttl = uint32(delta / time.Second)
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range section {
			if rr.Header().Ttl > ttl {
				rr.Header().Ttl = ttl
			}
		}
	}
	return secure
}
