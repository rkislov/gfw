// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

// Package ddns reconciles committed DHCP leases with owned DNS records.
package ddns

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
)

type Updater interface {
	Set(context.Context, storage.DNSRecord) error
	Remove(context.Context, storage.DNSRecord) error
}
type Worker struct {
	store   storage.Store
	state   storage.DNSStore
	config  func() *config.Config
	log     *slog.Logger
	now     func() time.Time
	factory func(context.Context, config.DDNS) (Updater, func(), error)
	mu      sync.Mutex
	owner   string
}

func New(st storage.Store, cfg func() *config.Config, log *slog.Logger) (*Worker, error) {
	state, ok := st.(storage.DNSStore)
	if !ok {
		return nil, fmt.Errorf("DDNS requires persistent DNS state support")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{store: st, state: state, config: cfg, log: log, now: time.Now, factory: newSession}, nil
}
func (w *Worker) Run(ctx context.Context, wake <-chan struct{}) {
	for {
		cfg := w.config().DDNS
		if cfg.Enabled {
			budget := time.Duration(cfg.IntervalSeconds) * time.Second
			if budget < time.Duration(cfg.TimeoutSeconds)*time.Second {
				budget = time.Duration(cfg.TimeoutSeconds) * time.Second
			}
			cycle, cancel := context.WithTimeout(ctx, budget)
			if err := w.Reconcile(cycle); err != nil && ctx.Err() == nil {
				w.log.Warn("ddns synchronization failed; will retry", "err", err)
			}
			cancel()
		}
		delay := time.Duration(cfg.IntervalSeconds) * time.Second
		if delay <= 0 {
			delay = 30 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-wake:
			timer.Stop()
			// Coalesce bursts of DHCP acknowledgements before acquiring a ticket.
			batch := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				batch.Stop()
				return
			case <-batch.C:
			}
		case <-timer.C:
		}
	}
}
func canonical(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) + "." }
func serverKey(c config.DDNS) string {
	return net.JoinHostPort(strings.ToLower(c.Server), strconv.Itoa(c.Port))
}
func Hostname(host string, c config.DDNS) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	zone := canonical(c.Zone)
	if !config.DNSName(host) {
		return "", false
	}
	if !strings.Contains(host, ".") {
		host += "." + strings.TrimSuffix(zone, ".")
	}
	name := canonical(host)
	if name == zone || !strings.HasSuffix(name, "."+zone) || len(name) > 230 {
		return "", false
	}
	first := strings.Split(name, ".")[0]
	if first == "wpad" || first == "isatap" || first == "autodiscover" || name == canonical(c.Server) {
		return "", false
	}
	for _, protected := range c.ProtectedNames {
		if !strings.Contains(strings.TrimSuffix(protected, "."), ".") {
			protected += "." + strings.TrimSuffix(zone, ".")
		}
		if name == canonical(protected) {
			return "", false
		}
	}
	return name, true
}
func enabled(v *bool) bool { return v == nil || *v }
func desired(cfg *config.Config, leases []model.Lease, owner string, now time.Time) (map[string]storage.DNSRecord, map[string]bool) {
	c := cfg.DDNS
	records := map[string]storage.DNSRecord{}
	blocked := map[string]bool{}
	type binding struct {
		lease model.Lease
		name  string
		ip    netip.Addr
	}
	bindings := []binding{}
	seen := map[string]string{}
	for _, l := range leases {
		if l.State != model.StateBound || !l.ExpiresAt.After(now) || l.Hostname == "" {
			continue
		}
		host := l.Hostname
		if !enabled(c.Hostname) {
			host = ""
			for _, r := range cfg.AllReservations() {
				if r.IP == l.IP && r.SubnetID == l.SubnetID {
					host = r.Hostname
					break
				}
			}
		}
		name, ok := Hostname(host, c)
		if !ok {
			continue
		}
		ip, e := netip.ParseAddr(l.IP)
		if e != nil || !ip.Is4() {
			continue
		}
		identity := l.MAC + "|" + l.ClientID + "|" + l.IP
		if old, ok := seen[name]; ok && old != identity {
			blocked[name] = true
		}
		seen[name] = identity
		bindings = append(bindings, binding{l, name, ip})
	}
	for _, b := range bindings {
		if blocked[b.name] {
			continue
		}
		mac := hmac.New(sha256.New, []byte(owner))
		mac.Write([]byte(b.lease.MAC + "\x00" + b.lease.ClientID + "\x00" + b.name))
		token := hex.EncodeToString(mac.Sum(nil))
		ttl := c.TTL
		if remaining := uint32(b.lease.ExpiresAt.Sub(now) / time.Second); remaining < ttl {
			ttl = remaining
		}
		if ttl < 1 {
			ttl = 1
		}
		add := func(zone, name, typ, value string) {
			r := storage.DNSRecord{Server: serverKey(c), Zone: canonical(zone), Name: name, Type: typ, Value: value, Token: token, TTL: ttl, LeaseExpires: b.lease.ExpiresAt.UTC()}
			records[r.Key()] = r
		}
		if enabled(c.UpdateA) {
			add(c.Zone, b.name, "A", b.ip.String())
		}
		if enabled(c.UpdatePTR) {
			octets := b.ip.As4()
			reverse := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])
			zone := ""
			for _, z := range c.Zones() {
				z = canonical(z)
				if strings.HasSuffix(reverse, "."+z) && len(z) > len(zone) {
					zone = z
				}
			}
			if zone != "" {
				add(zone, reverse, "PTR", b.name)
			}
		}
	}
	return records, blocked
}
func inScope(c config.DDNS, r storage.DNSRecord) bool {
	if r.Server != serverKey(c) {
		return false
	}
	if r.Type == "A" {
		return r.Zone == canonical(c.Zone)
	}
	if r.Type == "PTR" {
		for _, z := range c.Zones() {
			if r.Zone == canonical(z) {
				return true
			}
		}
	}
	return false
}
func (w *Worker) Reconcile(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cfg := w.config()
	c := cfg.DDNS
	if !c.Enabled {
		return nil
	}
	if err := config.ValidateDDNS(c); err != nil {
		return err
	}
	if w.owner == "" {
		owner, e := w.state.InitDNS(ctx)
		if e != nil {
			return e
		}
		w.owner = owner
	}
	now := w.now()
	leases, e := w.store.ActiveLeases(ctx, now)
	if e != nil {
		return e
	}
	want, blocked := desired(cfg, leases, w.owner, now)
	previous, e := w.state.DNSRecords(ctx)
	if e != nil {
		return e
	}
	if len(want) == 0 && len(previous) == 0 {
		return nil
	}
	client, closeSession, e := w.factory(ctx, c)
	if e != nil {
		return e
	}
	defer closeSession()
	current := map[string]storage.DNSRecord{}
	unavailable := map[string]bool{}
	for _, old := range previous {
		if !inScope(c, old) {
			continue
		} // Changing server/zones never deletes from an unconfigured authority.
		current[old.Key()] = old
		if blocked[old.Name] || (old.Type == "PTR" && blocked[old.Value]) {
			continue
		}
		next, exists := want[old.Key()]
		if exists && next.Token == old.Token {
			continue
		}
		if err := client.Remove(ctx, old); err != nil {
			unavailable[old.Key()] = true
			w.log.Warn("ddns delete failed; will retry", "name", old.Name, "type", old.Type, "err", err)
			continue
		}
		if err := w.state.DeleteDNSRecord(ctx, old.Key()); err != nil {
			return err
		}
		delete(current, old.Key())
		w.log.Info("ddns deleted", "name", old.Name, "type", old.Type)
	}
	keys := make([]string, 0, len(want))
	for key := range want {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := want[keys[i]], want[keys[j]]
		if a.Type != b.Type {
			return a.Type == "A"
		}
		return keys[i] < keys[j]
	})
	failedNames := map[string]bool{}
	for _, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if unavailable[key] {
			if want[key].Type == "A" {
				failedNames[want[key].Name] = true
			}
			continue
		}
		next := want[key]
		if next.Type == "PTR" && enabled(c.UpdateA) && failedNames[next.Value] {
			continue
		}
		old, exists := current[key]
		refresh := time.Duration(next.TTL) * time.Second / 2
		if exists && old.Token == next.Token && old.Value == next.Value && old.TTL == next.TTL && old.LeaseExpires.Equal(next.LeaseExpires) && !old.AppliedAt.IsZero() && now.Sub(old.AppliedAt) < refresh {
			continue
		}
		// Store the intent before sending; a crash after DNS succeeds is recoverable.
		if err := w.state.PutDNSRecord(ctx, next); err != nil {
			return err
		}
		if err := client.Set(ctx, next); err != nil {
			if next.Type == "A" {
				failedNames[next.Name] = true
			}
			w.log.Warn("ddns update failed; will retry", "name", next.Name, "type", next.Type, "err", err)
			continue
		}
		next.AppliedAt = now
		if err := w.state.PutDNSRecord(ctx, next); err != nil {
			return err
		}
		w.log.Info("ddns updated", "name", next.Name, "type", next.Type, "value", next.Value)
	}
	for name := range blocked {
		w.log.Warn("ddns duplicate hostname; existing records preserved", "name", name)
	}
	return nil
}
