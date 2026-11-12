// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"github.com/miekg/dns"
	"hash/maphash"
	"sync"
	"time"
)

type cacheEntry struct {
	msg *dns.Msg
	at  time.Time
	ttl uint32
}
type cacheShard struct {
	sync.RWMutex
	items    map[string]cacheEntry
	capacity int
}
type cache struct {
	seed   maphash.Seed
	shards [64]cacheShard
	limit  int
}

func newCache(limit int) *cache {
	c := &cache{seed: maphash.MakeSeed(), limit: limit}
	for i := range c.shards {
		c.shards[i].items = map[string]cacheEntry{}
		c.shards[i].capacity = limit / 64
		if i < limit%64 {
			c.shards[i].capacity++
		}
	}
	return c
}
func (c *cache) shard(k string) *cacheShard { return &c.shards[maphash.String(c.seed, k)%64] }

// A cache hit owns its message, OPT and Additional slice in one allocation.
// RR payloads still receive the library's deep copy before TTL adjustment.
type cachedReply struct {
	msg   dns.Msg
	opt   dns.OPT
	extra [1]dns.RR
}

func (c *cache) get(k string) *dns.Msg { return c.getReply(k, false) }
func (c *cache) getReply(k string, edns bool) *dns.Msg {
	s := c.shard(k)
	s.RLock()
	e, ok := s.items[k]
	s.RUnlock()
	if !ok {
		return nil
	}
	now := time.Now()
	elapsed := now.Sub(e.at)
	if elapsed < 0 {
		return nil
	}
	age := uint32(elapsed / time.Second)
	if age >= e.ttl {
		return nil
	}
	if e.msg.AuthenticatedData {
		for _, records := range [][]dns.RR{e.msg.Answer, e.msg.Ns} {
			for _, rr := range records {
				if sig, ok := rr.(*dns.RRSIG); ok && !sig.ValidityPeriod(now) {
					return nil
				}
			}
		}
	}
	var m *dns.Msg
	if edns {
		reply := new(cachedReply)
		reply.opt.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}
		m = e.msg.CopyTo(&reply.msg)
		reply.extra[0] = &reply.opt
		m.Extra = reply.extra[:]
	} else {
		m = e.msg.Copy()
	}
	for _, set := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range set {
			if rr.Header().Rrtype != dns.TypeOPT {
				if rr.Header().Ttl > age {
					rr.Header().Ttl -= age
				} else {
					rr.Header().Ttl = 0
				}
			}
		}
	}
	return m
}
func (c *cache) put(k string, m *dns.Msg) {
	if c.limit == 0 || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) || m.Truncated || (len(m.Answer) == 0 && !hasSOA(m.Ns)) {
		return
	}
	ttl := uint32(86400)
	if len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < ttl {
				ttl = soa.Minttl
			}
		}
	}
	for _, set := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range set {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if ttl == 0 {
		return
	}
	s := c.shard(k)
	if s.capacity == 0 {
		return
	}
	s.Lock()
	defer s.Unlock()
	if len(s.items) >= s.capacity {
		for key := range s.items {
			delete(s.items, key)
			break
		}
	}
	// The request question is restored by Resolve; Additional is rebuilt for
	// the client. Do not allocate copies of either on every cache hit.
	stored := *m
	stored.Question = nil
	stored.Extra = nil
	s.items[k] = cacheEntry{stored.Copy(), time.Now(), ttl}
}
