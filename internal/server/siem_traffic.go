package server

import (
	"context"
	"os"
	"time"

	"github.com/rkislov/gfw/internal/siem"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) RunSIEMTraffic(ctx context.Context) {
	host, _ := os.Hostname()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if s.processSIEMTraffic(ctx, host) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) processSIEMTraffic(ctx context.Context, host string) bool {
	// A successful filter update must not leave a worker sending batches with
	// the old settings. This lock is independent of the ClickHouse writer.
	s.siemTrafficConfigMu.Lock()
	defer s.siemTrafficConfigMu.Unlock()
	cfg, err := s.Store.ReadSIEM(ctx)
	if err != nil || !cfg.Enabled || !cfg.Traffic.Enabled() {
		return false
	}
	more, err := s.forwardTrafficSIEM(ctx, cfg, host)
	s.siemMu.Lock()
	s.siemTrafficRevision = cfg.Revision
	s.siemTrafficError = ""
	if err != nil {
		s.siemTrafficError = err.Error()
	}
	s.siemMu.Unlock()
	return err == nil && more
}

func (s *Server) forwardTrafficSIEM(ctx context.Context, cfg store.SIEM, host string) (bool, error) {
	batch, err := s.Store.PeekSIEMTraffic(ctx)
	if err != nil || len(batch.Events) == 0 {
		return false, err
	}
	match, err := cfg.Traffic.Compile()
	if err != nil {
		return false, err
	}
	messages := make([]string, 0, len(batch.Events))
	for _, event := range batch.Events {
		if match(event) {
			messages = append(messages, siem.TrafficEvent(host, version, event))
		}
	}
	if err := destination(cfg).Send(ctx, messages); err != nil {
		return false, err
	}
	err = s.Store.AckSIEMTraffic(ctx, cfg.Revision, batch.Cursor, len(messages) > 0)
	return len(batch.Events) == store.SIEMTrafficBatch, err
}
