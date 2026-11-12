// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/metrics"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/pool"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
)

// Prober checks whether an address is already in use on the wire.
type Prober interface {
	Reachable(ctx context.Context, ip netip.Addr, timeout time.Duration) (bool, error)
}

// Service is the DHCP core: config snapshot, pools and lease persistence.
type Service struct {
	// Serializes lease read/modify/write operations and pool reconciliation.
	// mu only protects publication of the immutable configuration snapshot.
	stateMu        sync.Mutex
	needsReconcile bool
	mu             sync.RWMutex
	snap           *Snapshot
	store          storage.Store
	pools          *pool.Manager
	log            *slog.Logger
	metrics        *metrics.Metrics
	prober         Prober
	now            func() time.Time
	statsMu        sync.Mutex
	stats          map[string]*model.RelayStats
	onBound        func(model.Lease)
	gen            int64
}

// Options configures a Service.
type Options struct {
	Store   storage.Store
	Config  *config.Config
	Logger  *slog.Logger
	Metrics *metrics.Metrics
	Prober  Prober
	Now     func() time.Time
	OnBound func(model.Lease)
}

// New loads the configuration into memory and the catalog tables.
func New(ctx context.Context, opt Options) (*Service, error) {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Metrics == nil {
		opt.Metrics = metrics.New()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	s := &Service{
		store:   opt.Store,
		pools:   pool.New(),
		log:     opt.Logger,
		metrics: opt.Metrics,
		prober:  opt.Prober,
		now:     opt.Now,
		stats:   map[string]*model.RelayStats{},
		onBound: opt.OnBound,
	}
	opt.Metrics.SetSource(s)
	if opt.Config != nil {
		if err := s.Apply(ctx, opt.Config); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Apply validates and installs a configuration without dropping the process.
func (s *Service) Apply(ctx context.Context, cfg *config.Config) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if cfg == nil {
		return fmt.Errorf("core: nil config")
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.mu.Unlock()
	snap, err := buildSnapshot(cfg, gen)
	if err != nil {
		return err
	}
	vlans, subnets, relays, reservations := catalogParts(snap)
	if err := s.store.ReplaceCatalog(ctx, storage.Catalog{
		VLANs: vlans, Subnets: subnets, Relays: relays, Reservations: reservations,
	}); err != nil {
		return err
	}
	leases, err := s.store.ActiveLeases(ctx, s.now())
	if err != nil {
		return err
	}
	s.pools.Reconcile(snap.Pools, bindingsOf(leases))
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
	s.log.Info("configuration applied", "subnets", len(snap.Subnets), "vlans", len(cfg.VLANs))
	return nil
}

// Config returns the active configuration.
func (s *Service) Config() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.snap == nil {
		return nil
	}
	return s.snap.Cfg
}

// Snapshot returns the active snapshot.
func (s *Service) current() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Store exposes persistence for the API.
func (s *Service) Store() storage.Store { return s.store }

// PoolStats implements metrics.Source.
func (s *Service) PoolStats() []metrics.PoolStat {
	stats := s.pools.Stats()
	out := make([]metrics.PoolStat, 0, len(stats))
	for _, st := range stats {
		out = append(out, metrics.PoolStat{
			Subnet: st.ID,
			VLAN:   strconv.Itoa(st.VLAN),
			Active: st.Used,
			Total:  st.Size,
		})
	}
	return out
}

// RelayStats returns counters for one relay, or all of them when giaddr is empty.
func (s *Service) RelayStats(giaddr string) []model.RelayStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if giaddr != "" {
		if st, ok := s.stats[giaddr]; ok {
			return []model.RelayStats{*st}
		}
		return nil
	}
	out := make([]model.RelayStats, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	return out
}

func (s *Service) noteRelay(giaddr, circuit, remote string, vlan *int, unknown bool) {
	if giaddr == "" {
		return
	}
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	st, ok := s.stats[giaddr]
	if !ok {
		st = &model.RelayStats{GIAddr: giaddr}
		s.stats[giaddr] = st
	}
	st.Requests++
	st.LastSeen = s.now()
	st.LastCircuit = circuit
	st.LastRemoteID = remote
	st.LastVLAN = vlan
	if unknown {
		st.UnknownVLAN++
	}
}

// ExpireOnce marks elapsed leases and returns their addresses to the pools.
func (s *Service) ExpireOnce(ctx context.Context) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	n, err := s.store.ExpireLeases(ctx, s.now())
	if err != nil || n == 0 {
		return err
	}
	leases, err := s.store.ActiveLeases(ctx, s.now())
	if err != nil {
		return err
	}
	if snap := s.current(); snap != nil {
		s.pools.Reconcile(snap.Pools, bindingsOf(leases))
	}
	s.log.Info("expired leases", "count", n)
	return nil
}

// RunJanitor expires leases until the context is cancelled.
func (s *Service) RunJanitor(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.ExpireOnce(ctx); err != nil {
				s.log.Error("expire leases", "err", err)
			}
		}
	}
}

// DeleteLease removes a binding and frees the address.
func (s *Service) DeleteLease(ctx context.Context, ip string) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	l, err := s.store.GetLease(ctx, ip)
	if err != nil {
		return err
	}
	if err := s.store.DeleteLease(ctx, ip); err != nil {
		return err
	}
	s.pools.Release(ip, l.MAC)
	return nil
}
