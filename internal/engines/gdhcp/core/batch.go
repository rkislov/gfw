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
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
)

type leaseBatchStore interface {
	WithLeaseTransaction(context.Context, func(context.Context) error) error
}
type boundBatchKey struct{}

// HandleBatch shares one durable database commit across a bounded group of
// already-received datagrams. No reply or bound callback escapes before commit.
// A failed SQL group is rolled back in full; clients may retry unanswered packets.
// Stores without transaction support retain sequential per-packet commits.
func (s *Service) HandleBatch(ctx context.Context, inputs []Input) ([]*Output, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	txStore, ok := s.store.(leaseBatchStore)
	if len(inputs) == 1 || !ok {
		outputs := make([]*Output, len(inputs))
		for i, in := range inputs {
			var err error
			outputs[i], err = s.Handle(ctx, in)
			if err != nil {
				return nil, err
			}
		}
		return outputs, nil
	}
	start := time.Now()
	defer func() {
		elapsed := time.Since(start).Seconds()
		for range inputs {
			s.metrics.Duration.Observe(elapsed)
		}
	}()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.needsReconcile {
		if err := s.restorePools(ctx); err != nil {
			return nil, err
		}
	}
	outputs := make([]*Output, len(inputs))
	var bound []model.Lease
	err := txStore.WithLeaseTransaction(ctx, func(txCtx context.Context) error {
		txCtx = context.WithValue(txCtx, boundBatchKey{}, &bound)
		for i, in := range inputs {
			var err error
			outputs[i], err = s.handleLocked(txCtx, in)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The original context may be cancelled. Recovery must inspect committed
		// storage, not the transaction that has just been rolled back.
		s.needsReconcile = true
		recovery, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if restoreErr := s.restorePools(recovery); restoreErr != nil {
			return nil, fmt.Errorf("lease batch failed: %w; restore: %v", err, restoreErr)
		}
		return nil, err
	}
	for _, lease := range bound {
		if s.onBound != nil {
			go s.onBound(lease)
		}
	}
	return outputs, nil
}

func (s *Service) notifyBound(ctx context.Context, l model.Lease) {
	if s.onBound == nil {
		return
	}
	if pending, ok := ctx.Value(boundBatchKey{}).(*[]model.Lease); ok {
		*pending = append(*pending, l)
		return
	}
	go s.onBound(l)
}

func (s *Service) restorePools(ctx context.Context) error {
	leases, err := s.store.ActiveLeases(ctx, s.now())
	if err != nil {
		return err
	}
	if snap := s.current(); snap != nil {
		s.pools.Reconcile(snap.Pools, bindingsOf(leases))
	}
	s.needsReconcile = false
	return nil
}
