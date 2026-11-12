// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListenBindsBeforeServingAndCancellationReleasesSocket(t *testing.T) {
	listener, err := Listen("127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.conn.LocalAddr().String()
	other, err := Listen(addr)
	require.Error(t, err)
	require.Nil(t, other)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- listener.Serve(ctx, nil, nil) }()
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("UDP serve did not stop")
	}
	reopened, err := Listen(addr)
	require.NoError(t, err)
	reopened.Close()
}
