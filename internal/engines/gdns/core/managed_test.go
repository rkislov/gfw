// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	validation "github.com/rkislov/gfw/internal/engines/gdns/dnssec"
	"github.com/miekg/dns"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedRevocationInvalidatesCacheAndSurvivesRestart(t *testing.T) {
	for _, mode := range []string{"active", "passive", "storage-failure", "slow-revocation-commit"} {
		t.Run(mode, func(t *testing.T) {
			key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: 1, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
			private, err := key.Generate(256)
			if err != nil {
				t.Fatal(err)
			}
			sign := func(k *dns.DNSKEY, record dns.RR) []dns.RR {
				sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 300}, TypeCovered: record.Header().Rrtype, Algorithm: k.Algorithm, OrigTtl: 300, Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()), KeyTag: k.KeyTag(), SignerName: "."}
				if err := sig.Sign(private.(crypto.Signer), []dns.RR{record}); err != nil {
					t.Fatal(err)
				}
				return []dns.RR{record, sig}
			}
			txt, _ := dns.NewRR(`. 300 IN TXT "authenticated"`)
			data := sign(key, txt)
			keys := sign(key, key)
			revKey := *key
			revKey.Flags |= 128
			revokedKeys := sign(&revKey, &revKey)
			var revoked atomic.Bool
			var writes atomic.Int64
			entered := make(chan struct{})
			release := make(chan struct{})
			var held atomic.Bool
			server := fakeDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(q)
				m.Answer = copyRRs(data, "")
				if q.Question[0].Qtype == dns.TypeDNSKEY {
					m.Answer = copyRRs(keys, "")
					if revoked.Load() {
						m.Answer = copyRRs(revokedKeys, "")
					}
				}
				_ = w.WriteMsg(m)
			})
			c := DefaultConfig()
			c.Mode = "forward"
			c.Upstreams = []string{server}
			c.DNSSECValidation = true
			c.DNSSEC.AutoUpdate.Enabled = mode != "passive"
			c.DNSSEC.TrustAnchors = []string{key.ToDS(dns.SHA256).String()}
			identityKey := *key
			identityKey.Hdr.Ttl = 0
			sum := sha256.Sum256([]byte(identityKey.String()))
			id := hex.EncodeToString(sum[:])
			disk := validation.ManagedState{Version: 1, Revision: 1, Seeds: validation.RootSeeds(c.DNSSEC), Keys: []validation.ManagedKey{{ID: id, Key: key.String(), Tag: key.KeyTag(), State: validation.Valid, FirstSeen: time.Now().Add(-time.Hour)}}, UpdatedAt: time.Now().Add(-time.Hour)}
			load := func(context.Context) (*validation.ManagedState, error) { copy := disk; return &copy, nil }
			save := func(_ context.Context, s validation.ManagedState) (int64, error) {
				writes.Add(1)
				if mode == "slow-revocation-commit" && len(s.Keys) > 0 && s.Keys[0].State == validation.Revoked && held.CompareAndSwap(false, true) {
					close(entered)
					<-release
				}
				if mode == "storage-failure" {
					return 0, errors.New("disk failure")
				}
				s.Revision++
				disk = s
				return s.Revision, nil
			}
			manager, err := validation.OpenManager(context.Background(), load, save)
			if err != nil {
				t.Fatal(err)
			}
			e, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.SetRootManager(manager); err != nil {
				t.Fatal(err)
			}
			resolve := func(typ uint16) *dns.Msg {
				q := query(".", typ)
				q.SetEdns0(1232, true)
				m, _ := e.Resolve(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
				return m
			}
			for i := 0; i < 3; i++ {
				if m := resolve(dns.TypeTXT); m.Rcode != 0 || !m.AuthenticatedData {
					t.Fatalf("warm secure cache: %v", m)
				}
			}
			if writes.Load() != 0 {
				t.Fatal("SQL on ordinary DNS path")
			}
			revoked.Store(true)
			if mode == "slow-revocation-commit" {
				done := make(chan error, 1)
				go func() { done <- e.RefreshRootAnchors(context.Background()) }()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("revocation save did not start")
				}
				m := resolve(dns.TypeTXT)
				close(release)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if m.Rcode != dns.RcodeServerFailure || m.AuthenticatedData {
					t.Fatal("revoked cached trust used while persistence was pending")
				}
			} else if mode == "passive" {
				resolve(dns.TypeDNSKEY)
			} else {
				err = e.RefreshRootAnchors(context.Background())
				if mode == "storage-failure" && err == nil {
					t.Fatal("save failure hidden")
				}
				if mode == "active" && err != nil {
					t.Fatal(err)
				}
			}
			if m := resolve(dns.TypeTXT); m.Rcode != dns.RcodeServerFailure || m.AuthenticatedData {
				t.Fatalf("old secure cache survived revocation: %v", m)
			}
			c.DNSSEC.AutoUpdate.Enabled = false
			if err = e.Apply(c); err != nil {
				t.Fatal(err)
			}
			if m := resolve(dns.TypeTXT); m.Rcode != dns.RcodeServerFailure {
				t.Fatal("pause restored bootstrap trust")
			}
			if mode != "storage-failure" {
				reloaded, err := validation.OpenManager(context.Background(), load, save)
				if err != nil {
					t.Fatal(err)
				}
				fresh, _ := New(c)
				if err = fresh.SetRootManager(reloaded); err != nil {
					t.Fatal(err)
				}
				q := query(".", dns.TypeTXT)
				q.SetEdns0(1232, true)
				m, _ := fresh.Resolve(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
				if m.Rcode != dns.RcodeServerFailure {
					t.Fatal("restart resurrected revoked root")
				}
			}
		})
	}
}
