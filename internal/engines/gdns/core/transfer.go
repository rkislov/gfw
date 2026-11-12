// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"reflect"
	"sort"
	"time"
)

type ZoneTransfer struct {
	Allow   []string `json:"allow,omitempty"`
	KeyName string   `json:"key_name,omitempty"`
	Secret  string   `json:"secret,omitempty"`
}
type SecondaryState struct {
	LastSuccess time.Time `json:"last_success,omitempty"`
	NextRefresh time.Time `json:"next_refresh,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Serial      uint32    `json:"serial"`
}

func validateTransfer(z Zone, zones []Zone) error {
	if _, err := prefixes(z.Transfer.Allow); err != nil {
		return err
	}
	if z.Kind != "primary" && z.Kind != "secondary" && (len(z.Transfer.Allow) > 0 || z.Transfer.KeyName != "" || z.Transfer.Secret != "") {
		return fmt.Errorf("transfer settings require an authoritative zone")
	}
	if z.Transfer.KeyName == "" && z.Transfer.Secret == "" {
		return nil
	}
	if !validName(z.Transfer.KeyName) || z.Transfer.KeyName == "" {
		return fmt.Errorf("invalid TSIG key name")
	}
	key, err := base64.StdEncoding.DecodeString(z.Transfer.Secret)
	if err != nil || len(key) < 32 || len(key) > 128 {
		return fmt.Errorf("TSIG secret must be base64 with 32..128 bytes")
	}
	for _, other := range zones {
		if other.Transfer.KeyName != "" && canonical(other.Transfer.KeyName) == canonical(z.Transfer.KeyName) && other.Transfer.Secret != z.Transfer.Secret {
			return fmt.Errorf("TSIG key name has conflicting secrets")
		}
	}
	return nil
}

// Engine implements dns.TsigProvider so configuration changes take effect without restart.
func (e *Engine) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	if dns.CanonicalName(t.Algorithm) != dns.HmacSHA256 {
		return nil, dns.ErrKeyAlg
	}
	for _, z := range e.state.Load().snap.config.Zones {
		if z.Transfer.KeyName != "" && canonical(z.Transfer.KeyName) == canonical(t.Hdr.Name) {
			key, err := base64.StdEncoding.DecodeString(z.Transfer.Secret)
			if err != nil {
				return nil, err
			}
			h := hmac.New(sha256.New, key)
			h.Write(msg)
			return h.Sum(nil), nil
		}
	}
	return nil, dns.ErrSecret
}
func (e *Engine) Verify(msg []byte, t *dns.TSIG) error {
	want, err := e.Generate(msg, t)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, got) {
		return dns.ErrSig
	}
	return nil
}
func secondaryAvailable(z *compiledZone, now time.Time) bool {
	return len(z.soa) == 1 && !z.Secondary.LastSuccess.IsZero() && now.Before(z.Secondary.LastSuccess.Add(time.Duration(z.soa[0].(*dns.SOA).Expire)*time.Second))
}
func (e *Engine) serveAXFR(w dns.ResponseWriter, q *dns.Msg) {
	refuse := func() { _ = w.WriteMsg(newReply(q, dns.RcodeRefused)) }
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp || q.Opcode != dns.OpcodeQuery || q.Question[0].Qclass != dns.ClassINET {
		refuse()
		return
	}
	ip := ClientIP(w.RemoteAddr()).Unmap()
	z := e.state.Load().snap.zone(canonical(q.Question[0].Name), ip)
	if z == nil || z.Name != canonical(q.Question[0].Name) || z.Kind != "primary" && z.Kind != "secondary" || z.Kind == "secondary" && !secondaryAvailable(z, time.Now()) {
		refuse()
		return
	}
	ps, _ := prefixes(z.Transfer.Allow)
	allowed := false
	for _, p := range ps {
		if p.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		refuse()
		return
	}
	tsig := q.IsTsig()
	if tsig != nil && w.TsigStatus() != nil {
		refuse()
		return
	}
	if z.Transfer.KeyName != "" && (tsig == nil || canonical(tsig.Hdr.Name) != canonical(z.Transfer.KeyName) || dns.CanonicalName(tsig.Algorithm) != dns.HmacSHA256) {
		refuse()
		return
	}
	// Enumerate the effective source view, including names only present in overlays.
	names := map[string]bool{}
	for n := range z.records {
		names[n] = true
	}
	for p, l := range z.recordViews {
		if p.Contains(ip) {
			for n := range l.records {
				names[n] = true
			}
		}
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	records := []dns.RR{dns.Copy(z.soa[0])}
	for _, n := range ordered {
		sets, _ := z.recordsFor(n, ip)
		types := make([]int, 0, len(sets))
		for typ := range sets {
			if typ != dns.TypeSOA {
				types = append(types, int(typ))
			}
		}
		sort.Ints(types)
		for _, typ := range types {
			records = append(records, copyRRs(sets[uint16(typ)], "")...)
		}
	}
	records = append(records, dns.Copy(z.soa[0]))
	// Small bounded messages avoid oversized TCP frames even for large individual RRs.
	for len(records) > 0 {
		end := 0
		size := 64 + len(z.Name)
		for end < len(records) && size+dns.Len(records[end]) < 60000 {
			size += dns.Len(records[end])
			end++
		}
		if end == 0 {
			return
		}
		r := newReply(q, dns.RcodeSuccess)
		r.Authoritative = true
		r.Answer = records[:end]
		if tsig != nil {
			r.SetTsig(tsig.Hdr.Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
		}
		if w.WriteMsg(r) != nil {
			return
		}
		w.TsigTimersOnly(true)
		records = records[end:]
	}
}
func serialNewer(a, b uint32) bool { return a != b && a-b < 1<<31 }
func zoneSOA(z Zone) *dns.SOA {
	for _, line := range z.Records {
		rr, err := dns.NewRR(line)
		if err == nil {
			if soa, ok := rr.(*dns.SOA); ok && canonical(soa.Hdr.Name) == canonical(z.Name) {
				return soa
			}
		}
	}
	return nil
}
func SecondaryRetry(z Zone) time.Duration {
	if soa := zoneSOA(z); soa != nil {
		return max(5*time.Second, time.Duration(soa.Retry)*time.Second)
	}
	return 30 * time.Second
}
func signTransfer(q *dns.Msg, z Zone) map[string]string {
	if z.Transfer.KeyName == "" {
		return nil
	}
	name := canonical(z.Transfer.KeyName)
	q.SetTsig(name, dns.HmacSHA256, 300, time.Now().Unix())
	return map[string]string{name: z.Transfer.Secret}
}

// FetchSecondary returns a complete validated candidate, never mutating the live snapshot.
func FetchSecondary(ctx context.Context, z Zone) (Zone, error) {
	var last error
	for _, server := range z.Servers {
		candidate, err := fetchSecondary(ctx, z, server)
		if err == nil {
			return candidate, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = fmt.Errorf("no primary servers")
	}
	return z, last
}
func fetchSecondary(parent context.Context, z Zone, server string) (Zone, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(canonical(z.Name), dns.TypeSOA)
	q.RecursionDesired = false
	keys := signTransfer(q, z)
	c := &dns.Client{Net: "tcp", Timeout: 5 * time.Second, TsigSecret: keys}
	r, _, err := c.ExchangeContext(ctx, q, server)
	if err != nil {
		return z, fmt.Errorf("SOA query failed: %w", err)
	}
	if z.Transfer.KeyName != "" && r.IsTsig() == nil {
		return z, fmt.Errorf("unsigned SOA response")
	}
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) == 0 {
		return z, fmt.Errorf("primary did not return authoritative SOA")
	}
	soa, ok := r.Answer[0].(*dns.SOA)
	if !ok || canonical(soa.Hdr.Name) != canonical(z.Name) {
		return z, fmt.Errorf("invalid primary SOA")
	}
	if old := zoneSOA(z); old != nil && !z.Secondary.LastSuccess.IsZero() {
		if soa.Serial == old.Serial && time.Now().Before(z.Secondary.LastSuccess.Add(time.Duration(old.Expire)*time.Second)) {
			z.Secondary.LastSuccess = time.Now().UTC()
			z.Secondary.NextRefresh = time.Now().UTC().Add(max(5*time.Second, time.Duration(old.Refresh)*time.Second))
			z.Secondary.LastError = ""
			return z, nil
		}
		if soa.Serial != old.Serial && !serialNewer(soa.Serial, old.Serial) {
			return z, fmt.Errorf("primary SOA serial is older or ambiguous")
		}
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", server)
	if err != nil {
		return z, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	q = new(dns.Msg)
	q.SetAxfr(canonical(z.Name))
	keys = signTransfer(q, z)
	x := &dns.Transfer{Conn: &dns.Conn{Conn: conn}, TsigSecret: keys, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	ch, err := x.In(q, server)
	if err != nil {
		return z, err
	}
	var records []dns.RR
	size := 0
	var transferErr error
	for env := range ch {
		if transferErr != nil {
			continue
		}
		if env.Error != nil {
			transferErr = env.Error
			conn.Close()
			continue
		}
		for _, rr := range env.RR {
			size += dns.Len(rr)
			if len(records) >= 100000 || size > MaxImport {
				transferErr = fmt.Errorf("AXFR exceeds record or byte limit")
				conn.Close()
				break
			}
			records = append(records, rr)
		}
	}
	if transferErr != nil {
		return z, fmt.Errorf("AXFR failed: %w", transferErr)
	}
	if len(records) < 2 {
		return z, fmt.Errorf("incomplete AXFR")
	}
	first, ok := records[0].(*dns.SOA)
	last, lastOK := records[len(records)-1].(*dns.SOA)
	if !ok || !lastOK || first.String() != last.String() || canonical(first.Hdr.Name) != canonical(z.Name) {
		return z, fmt.Errorf("AXFR SOA boundaries differ")
	}
	if old := zoneSOA(z); old != nil && !z.Secondary.LastSuccess.IsZero() && first.Serial != old.Serial && !serialNewer(first.Serial, old.Serial) {
		return z, fmt.Errorf("AXFR serial rolled back")
	}
	z.Records = nil
	for _, rr := range records[:len(records)-1] {
		h := rr.Header()
		if h.Class != dns.ClassINET || !dns.IsSubDomain(canonical(z.Name), canonical(h.Name)) || h.Rrtype == dns.TypeTSIG || h.Rrtype == dns.TypeOPT {
			return z, fmt.Errorf("invalid AXFR record")
		}
		z.Records = append(z.Records, rr.String())
	}
	now := time.Now().UTC()
	z.Secondary = SecondaryState{LastSuccess: now, NextRefresh: now.Add(max(5*time.Second, time.Duration(first.Refresh)*time.Second)), Serial: first.Serial}
	return z, nil
}

// SecondarySchedule reads only metadata, never copying large record/feed lists.
func (e *Engine) SecondarySchedule() map[int]time.Time {
	out := map[int]time.Time{}
	for i, z := range e.state.Load().snap.config.Zones {
		if z.Kind == "secondary" {
			out[i] = z.Secondary.NextRefresh
		}
	}
	return out
}

// Editing data without advancing SOA must still notify polling secondaries.
func advancePrimarySerials(c *Config, old Config) {
	for i := range c.Zones {
		z := &c.Zones[i]
		if z.Kind != "primary" {
			continue
		}
		for _, prev := range old.Zones {
			if prev.Kind != "primary" || canonical(prev.Name) != canonical(z.Name) || !reflect.DeepEqual(prev.Clients, z.Clients) {
				continue
			}
			if reflect.DeepEqual(prev.Records, z.Records) && reflect.DeepEqual(prev.RecordViews, z.RecordViews) {
				break
			}
			before, after := zoneSOA(prev), zoneSOA(*z)
			if before == nil || after == nil || serialNewer(after.Serial, before.Serial) {
				break
			}
			after.Serial = before.Serial + 1
			for j, line := range z.Records {
				rr, err := dns.NewRR(line)
				if err == nil && rr.Header().Rrtype == dns.TypeSOA && canonical(rr.Header().Name) == canonical(z.Name) {
					z.Records[j] = after.String()
					break
				}
			}
			break
		}
	}
}

type SecondaryStatus struct {
	ID        int            `json:"id"`
	Name      string         `json:"name"`
	Available bool           `json:"available"`
	Expires   time.Time      `json:"expires"`
	State     SecondaryState `json:"state"`
}

func (e *Engine) SecondaryStatus() []SecondaryStatus {
	out := []SecondaryStatus{}
	for i, z := range e.state.Load().snap.config.Zones {
		if z.Kind != "secondary" {
			continue
		}
		v := SecondaryStatus{ID: i, Name: z.Name, State: z.Secondary}
		if soa := zoneSOA(z); soa != nil && !z.Secondary.LastSuccess.IsZero() {
			v.Expires = z.Secondary.LastSuccess.Add(time.Duration(soa.Expire) * time.Second)
			v.Available = time.Now().Before(v.Expires)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
