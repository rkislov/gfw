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
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/dhcp"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
)

type controlledBatchStore struct {
	storage.Store
	failCommit   bool
	failRecovery bool
	beforeCommit func()
}

func (s *controlledBatchStore) WithLeaseTransaction(ctx context.Context, fn func(context.Context) error) error {
	return s.Store.(leaseBatchStore).WithLeaseTransaction(ctx, func(txCtx context.Context) error {
		if err := fn(txCtx); err != nil {
			return err
		}
		if s.beforeCommit != nil {
			s.beforeCommit()
		}
		if s.failCommit {
			return errors.New("commit denied")
		}
		return nil
	})
}
func (s *controlledBatchStore) ActiveLeases(ctx context.Context, now time.Time) ([]model.Lease, error) {
	if s.failRecovery {
		return nil, errors.New("database unavailable")
	}
	return s.Store.ActiveLeases(ctx, now)
}
func batchRequests() []Input {
	return []Input{
		{Packet: leasePacket("02:00:00:00:00:71", dhcp.MsgRequest, netip.MustParseAddr("192.168.10.100")), VLAN: pint(10)},
		{Packet: leasePacket("02:00:00:00:00:72", dhcp.MsgRequest, netip.MustParseAddr("192.168.10.101")), VLAN: pint(10)},
	}
}

func TestBatchCommitsBeforeRepliesAndCallbacks(t *testing.T) {
	svc := safetyService(t)
	ctx := context.Background()
	called := make(chan model.Lease, 2)
	svc.onBound = func(l model.Lease) { called <- l }
	st := &controlledBatchStore{Store: svc.store}
	svc.store = st
	st.beforeCommit = func() {
		select {
		case <-called:
			t.Fatal("callback escaped before commit")
		default:
		}
	}
	outputs, err := svc.HandleBatch(ctx, batchRequests())
	require.NoError(t, err)
	require.Len(t, outputs, 2)
	for _, out := range outputs {
		require.Equal(t, dhcp.MsgAck, out.Packet.MessageType())
		lease, err := svc.store.GetLease(ctx, out.Packet.YIAddr.String())
		require.NoError(t, err)
		require.Equal(t, model.StateBound, lease.State)
	}
	for range 2 {
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("bound callback missing")
		}
	}
}

func TestFailedBatchRollsBackAndRestoresOccupancy(t *testing.T) {
	for _, failedRecovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "recovery unavailable"}[failedRecovery], func(t *testing.T) {
			svc := safetyService(t)
			ctx := context.Background()
			called := make(chan model.Lease, 2)
			svc.onBound = func(l model.Lease) { called <- l }
			st := &controlledBatchStore{Store: svc.store, failCommit: true, failRecovery: failedRecovery}
			svc.store = st
			outputs, err := svc.HandleBatch(ctx, batchRequests())
			require.ErrorContains(t, err, "commit denied")
			require.Nil(t, outputs)
			for _, in := range batchRequests() {
				ip, _ := in.Packet.RequestedIP()
				_, err := st.GetLease(ctx, ip.String())
				require.ErrorIs(t, err, storage.ErrNotFound)
			}
			select {
			case <-called:
				t.Fatal("rolled-back binding emitted callback")
			default:
			}
			if failedRecovery {
				require.True(t, svc.needsReconcile)
				out, err := svc.Handle(ctx, Input{Packet: discover("02:00:00:00:00:73", 3), VLAN: pint(10)})
				require.Error(t, err)
				require.Nil(t, out)
			}
			st.failCommit = false
			st.failRecovery = false
			out, err := svc.Handle(ctx, Input{Packet: discover("02:00:00:00:00:73", 3), VLAN: pint(10)})
			require.NoError(t, err)
			require.NotNil(t, out)
			require.Equal(t, "192.168.10.100", out.Packet.YIAddr.String())
			require.False(t, svc.needsReconcile)
		})
	}
}

func TestBatchFallbackAndEmptyInputs(t *testing.T) {
	svc := safetyService(t)
	ctx := context.Background()
	out, err := svc.HandleBatch(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, out)
	out, err = svc.HandleBatch(ctx, batchRequests()[:1])
	require.NoError(t, err)
	require.Len(t, out, 1)
	svc.store = &failingLeaseStore{Store: svc.store, err: errors.New("disk failed")}
	out, err = svc.HandleBatch(ctx, batchRequests())
	require.ErrorContains(t, err, "disk failed")
	require.Nil(t, out)
}

type cancelledCommitStore struct{ storage.Store }

func (s *cancelledCommitStore) WithLeaseTransaction(ctx context.Context, fn func(context.Context) error) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	return s.Store.(leaseBatchStore).WithLeaseTransaction(child, func(txCtx context.Context) error {
		if err := fn(txCtx); err != nil {
			return err
		}
		cancel()
		return nil
	})
}
func TestCancelledBatchCommitDoesNotPublishReplies(t *testing.T) {
	svc := safetyService(t)
	svc.store = &cancelledCommitStore{Store: svc.store}
	out, err := svc.HandleBatch(context.Background(), batchRequests())
	require.Error(t, err)
	require.Nil(t, out)
	for _, in := range batchRequests() {
		ip, _ := in.Packet.RequestedIP()
		_, err := svc.store.GetLease(context.Background(), ip.String())
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
}
