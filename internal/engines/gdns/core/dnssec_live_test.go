// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	validation "github.com/rkislov/gfw/internal/engines/gdns/dnssec"
	"github.com/miekg/dns"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestDNSSECLive(t *testing.T) {
	if os.Getenv("GDNS_DNSSEC_LIVE") == "" {
		t.Skip("opt-in Internet DNSSEC integration")
	}
	for _, mode := range []string{"forward", "recursive"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultConfig()
			c.Mode = mode
			c.DNSSECValidation = true
			e, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name string
				typ  uint16
				want int
				ad   bool
			}{{"cloudflare.com.", dns.TypeA, 0, true}, {"cloudflare.com.", dns.TypeDNSKEY, 0, true}, {"example.com.", dns.TypeA, 0, true}, {"dnssec-failed.org.", dns.TypeA, dns.RcodeServerFailure, false}, {"gdns-does-not-exist-20261105.cloudflare.com.", dns.TypeA, 0, true}, {"gdns-does-not-exist-20261105.se.", dns.TypeA, dns.RcodeNameError, true}, {"cloudflare.com.", dns.TypeDS, 0, true}, {"www.github.com.", dns.TypeA, 0, false}} {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				q := query(tc.name, tc.typ)
				q.SetEdns0(1232, true)
				m, result := e.Resolve(ctx, q, netip.MustParseAddr("127.0.0.1"))
				cancel()
				t.Logf("%s %s %s AD=%v answers=%d", tc.name, dns.TypeToString[tc.typ], result, m.AuthenticatedData, len(m.Answer))
				if m.Rcode != tc.want || m.AuthenticatedData != tc.ad {
					t.Errorf("unexpected result: %v", m)
				}
			}
		})
	}
}

func TestRFC5011Live(t *testing.T) {
	if os.Getenv("GDNS_DNSSEC_LIVE") == "" {
		t.Skip("opt-in Internet RFC 5011 integration")
	}
	for _, mode := range []string{"forward", "recursive"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultConfig()
			c.Mode = mode
			c.DNSSECValidation = true
			c.DNSSEC.AutoUpdate.Enabled = true
			writes := 0
			manager, err := validation.OpenManager(context.Background(), func(context.Context) (*validation.ManagedState, error) { return nil, nil }, func(_ context.Context, s validation.ManagedState) (int64, error) {
				writes++
				return s.Revision + 1, nil
			})
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
			original := e.Config()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err = e.RefreshRootAnchors(ctx); err != nil {
				t.Fatal(err)
			}
			status := manager.Status(e.Config().DNSSEC)
			if !status.Initialized || status.State != "healthy" || status.ActiveAnchors < 1 || len(status.Keys) < 1 || status.NextProbe.Before(time.Now().Add(59*time.Minute)) {
				t.Fatalf("%+v", status)
			}
			before := writes
			if err = e.RefreshRootAnchors(ctx); err != nil || writes != before {
				t.Fatal("live repeat bypassed cooldown", err)
			}
			if !reflect.DeepEqual(original, e.Config()) {
				t.Fatal("updater changed administrative configuration")
			}
			q := query("cloudflare.com.", dns.TypeA)
			q.SetEdns0(1232, true)
			m, _ := e.Resolve(ctx, q, netip.MustParseAddr("127.0.0.1"))
			if m.Rcode != 0 || !m.AuthenticatedData {
				t.Fatal(m)
			}
			t.Logf("RFC5011 %s: %d trusted anchors, %d tracked keys, next=%s", mode, status.ActiveAnchors, len(status.Keys), status.NextProbe)
		})
	}
}
