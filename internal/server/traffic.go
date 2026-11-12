package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/traffic"
	"github.com/rkislov/gfw/internal/vpncred"
)

type trafficManager struct {
	mu          sync.Mutex
	vault       *vpncred.Vault
	config      traffic.Destination
	client      *traffic.ClickHouse
	initialized bool
	lastError   string
	lastWrite   time.Time
}

func (s *Server) EnableTraffic(dir string) error {
	vault, err := vpncred.OpenVault(dir)
	if err != nil {
		return err
	}
	m := &trafficManager{vault: vault}
	if err = vault.Get("clickhouse", &m.config); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err = m.config.Validate(); err != nil {
		return err
	}
	if m.config.URL != "" {
		m.client = traffic.Connect(m.config)
	}
	s.traffic = m
	return nil
}

func (s *Server) trafficRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/traffic/status", s.trafficStatus)
	api.HandleFunc("PUT /api/v1/traffic/config", s.trafficConfig)
	api.HandleFunc("GET /api/v1/traffic/events", s.trafficEvents)
}

func (s *Server) trafficStatus(w http.ResponseWriter, r *http.Request) {
	m := s.traffic
	if m == nil {
		fail(w, 503, "Хранилище настроек журналирования недоступно")
		return
	}
	m.mu.Lock()
	conf, reason, last, ready := m.config, m.lastError, m.lastWrite, m.initialized
	m.mu.Unlock()
	conf.Password = ""
	var agent traffic.Status
	var agentError string
	if s.AgentSocket != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/traffic/status", nil, &agent); err != nil {
			agentError = "Коллектор агента недоступен"
		}
	} else {
		agentError = "Linux-агент не подключён"
	}
	respond(w, 200, map[string]any{"config": conf, "error": reason, "last_write": last, "ready": ready, "agent": agent, "agent_error": agentError})
}

func (s *Server) trafficConfig(w http.ResponseWriter, r *http.Request) {
	m := s.traffic
	if m == nil {
		fail(w, 503, "Хранилище настроек журналирования недоступно")
		return
	}
	var conf traffic.Destination
	if decode(w, r, &conf) != nil {
		fail(w, 400, "Некорректные настройки ClickHouse")
		return
	}
	if err := conf.Validate(); err != nil {
		fail(w, 422, err.Error())
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if conf.URL == "" {
		conf = traffic.Destination{}
	}
	if conf.Password == "" && conf.URL == m.config.URL && conf.User == m.config.User {
		conf.Password = m.config.Password
	}
	if err := m.vault.Put("clickhouse", conf); err != nil {
		s.internal(w, err)
		return
	}
	m.config = conf
	m.client = nil
	m.initialized = false
	m.lastError = ""
	m.lastWrite = time.Time{}
	if conf.URL != "" {
		m.client = traffic.Connect(conf)
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func (s *Server) trafficEvents(w http.ResponseWriter, r *http.Request) {
	m := s.traffic
	if m == nil {
		fail(w, 503, "ClickHouse не настроен")
		return
	}
	m.mu.Lock()
	client, ready := m.client, m.initialized
	m.mu.Unlock()
	if client == nil || !ready {
		fail(w, 503, "ClickHouse недоступен")
		return
	}
	events, err := client.Search(r.Context(), r.URL.Query())
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	respond(w, 200, events)
}

func (s *Server) RunTraffic(ctx context.Context) {
	if s.traffic == nil {
		return
	}
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			for range 8 {
				if ctx.Err() != nil || !s.deliverTraffic(ctx) {
					break
				}
			}
		}
	}
}

func (s *Server) deliverTraffic(ctx context.Context) bool {
	m := s.traffic
	m.mu.Lock()
	client, ready := m.client, m.initialized
	m.mu.Unlock()
	if client == nil {
		return false
	}
	if !ready {
		err := client.Init(ctx)
		m.mu.Lock()
		if m.client == client {
			m.initialized = err == nil
			if err != nil {
				m.lastError = err.Error()
			} else {
				m.lastError = ""
			}
		}
		m.mu.Unlock()
		if err != nil {
			return false
		}
	}
	if s.AgentSocket == "" {
		return false
	}
	op, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var batch traffic.Batch
	err := agentclient.Call(op, s.AgentSocket, "GET", "/v1/traffic/batch", nil, &batch)
	if err == nil && len(batch.Events) > 0 {
		err = client.Insert(op, batch)
		if err == nil {
			// Forwarding has its own durable queue and never gates the ClickHouse ACK.
			queueCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			queueErr := s.Store.EnqueueSIEMTraffic(queueCtx, batch.Events)
			cancel()
			s.siemMu.Lock()
			if queueErr != nil {
				if s.siemTrafficQueueError == "" {
					slog.Warn("SIEM traffic queue write failed", "error", queueErr)
				}
				s.siemTrafficQueueError = "Не удалось сохранить пакет событий в очереди SIEM"
			} else {
				s.siemTrafficQueueError = ""
			}
			s.siemMu.Unlock()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != client {
		return false
	}
	if err == nil && len(batch.Events) > 0 {
		var result map[string]bool
		ackCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = agentclient.Call(ackCtx, s.AgentSocket, "POST", "/v1/traffic/ack", map[string]int64{"cursor": batch.Cursor}, &result)
		cancel()
		if err == nil {
			m.lastWrite = time.Now().UTC()
		}
	}
	if err != nil {
		m.lastError = err.Error()
	} else {
		m.lastError = ""
	}
	return err == nil && len(batch.Events) == traffic.BatchSize
}
