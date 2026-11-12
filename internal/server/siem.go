package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/siem"
	"github.com/rkislov/gfw/internal/store"
	"github.com/rkislov/gfw/internal/traffic"
)

func destination(cfg store.SIEM) siem.Destination {
	return siem.Destination{Address: cfg.Address, Transport: cfg.Transport, CA: cfg.CA}
}

func (s *Server) siemRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/siem", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.Store.ReadSIEM(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		stats, err := s.Store.SIEMTrafficStats(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		s.siemMu.Lock()
		message := ""
		if cfg.Enabled && s.siemRevision == cfg.Revision {
			message = s.siemError
		}
		trafficError, queueError := "", s.siemTrafficQueueError
		if cfg.Enabled && cfg.Traffic.Enabled() && s.siemTrafficRevision == cfg.Revision {
			trafficError = s.siemTrafficError
		}
		s.siemMu.Unlock()
		respond(w, 200, struct {
			store.SIEM
			DeliveryError     string                 `json:"delivery_error,omitempty"`
			TrafficStats      store.SIEMTrafficStats `json:"traffic_stats"`
			TrafficError      string                 `json:"traffic_error,omitempty"`
			TrafficQueueError string                 `json:"traffic_queue_error,omitempty"`
		}{cfg, message, stats, trafficError, queueError})
	})
	api.HandleFunc("PUT /api/v1/siem", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Revision  int64                 `json:"revision"`
			Enabled   bool                  `json:"enabled"`
			Address   string                `json:"address"`
			Transport string                `json:"transport"`
			CA        string                `json:"ca_pem"`
			Traffic   *traffic.ExportFilter `json:"traffic"`
		}
		if decode(w, r, &in) != nil || in.Revision < 1 {
			fail(w, 400, "неверные настройки SIEM")
			return
		}
		cfg := store.SIEM{Traffic: in.Traffic, Revision: in.Revision, Enabled: in.Enabled, Address: strings.TrimSpace(in.Address), Transport: in.Transport, CA: strings.TrimSpace(in.CA)}
		if cfg.Traffic != nil {
			cfg.Traffic.IP = strings.TrimSpace(cfg.Traffic.IP)
			cfg.Traffic.Rule = strings.TrimSpace(cfg.Traffic.Rule)
			if _, err := cfg.Traffic.Compile(); err != nil {
				fail(w, 422, err.Error())
				return
			}
		}
		if cfg.Enabled || cfg.Address != "" || cfg.CA != "" {
			if err := destination(cfg).Validate(); err != nil {
				fail(w, 422, err.Error())
				return
			}
		} else if cfg.Transport != "tls" && cfg.Transport != "tcp" {
			fail(w, 422, "выберите TCP или TLS")
			return
		}
		s.siemTrafficConfigMu.Lock()
		err := s.Store.SaveSIEM(r.Context(), cfg, requestIdentity(r).Name)
		s.siemTrafficConfigMu.Unlock()
		if errors.Is(err, store.ErrConflict) {
			fail(w, 409, err.Error())
			return
		} else if err != nil {
			s.internal(w, err)
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	api.HandleFunc("POST /api/v1/siem/test", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.Store.ReadSIEM(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		dest := destination(cfg)
		if err := dest.Validate(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		actor := requestIdentity(r).Name
		if err := s.Store.LogAuditActor(r.Context(), actor, "siem.test.request", cfg.Revision); err != nil {
			s.internal(w, err)
			return
		}
		host, _ := os.Hostname()
		test := siem.Event(host, time.Now().UTC().Format(time.RFC3339Nano), version, "gfw.siem.test", "SIEM test", 2,
			siem.Field{Key: "suser", Value: actor})
		if err := dest.Send(r.Context(), []string{test}); err != nil {
			fail(w, 502, "не удалось отправить тестовое событие: "+err.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
}

func (s *Server) RunSIEM(ctx context.Context) {
	host, _ := os.Hostname()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if cfg, err := s.Store.ReadSIEM(ctx); err == nil && cfg.Enabled {
			moreAudit, auditErr := s.forwardAudit(ctx, cfg, host)
			moreIDS, idsErr := s.forwardIDS(ctx, cfg, host)
			err = errors.Join(auditErr, idsErr)
			s.siemMu.Lock()
			s.siemRevision = cfg.Revision
			s.siemError = ""
			if err != nil {
				s.siemError = err.Error()
			}
			s.siemMu.Unlock()
			if err == nil && (moreAudit || moreIDS) {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) forwardAudit(ctx context.Context, cfg store.SIEM, host string) (bool, error) {
	events, err := s.Store.AuditAfter(ctx, cfg.AuditCursor)
	if err != nil || len(events) == 0 {
		return false, err
	}
	messages := make([]string, 0, len(events))
	for _, event := range events {
		fields := []siem.Field{
			{Key: "externalId", Value: strconv.FormatInt(event.ID, 10)},
			{Key: "suser", Value: event.Actor},
			{Key: "act", Value: event.Action},
		}
		code, _, _ := strings.Cut(event.Action, ":")
		severity := 3
		if strings.HasPrefix(code, "vpn.disconnect.") {
			parts := strings.SplitN(event.Action, ":", 4)
			if len(parts) == 4 {
				fields = append(fields, siem.Field{Key: "duser", Value: parts[3]},
					siem.Field{Key: "cs1Label", Value: "VPN profile"}, siem.Field{Key: "cs1", Value: parts[1]},
					siem.Field{Key: "cs2Label", Value: "VPN session"}, siem.Field{Key: "cs2", Value: parts[2]})
			}
			if strings.HasSuffix(code, ".failed") {
				severity = 5
			}
		}
		messages = append(messages, siem.Event(host, event.At, version, code, "GFW administrative audit", severity, fields...))
	}
	if err := destination(cfg).Send(ctx, messages); err != nil {
		return false, err
	}
	return len(events) == 100, s.Store.AdvanceSIEM(ctx, cfg.Revision, events[len(events)-1].ID, 0)
}

func (s *Server) forwardIDS(ctx context.Context, cfg store.SIEM, host string) (bool, error) {
	if s.AgentSocket == "" {
		return false, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var alerts []ids.Alert
	if err := agentclient.Call(queryCtx, s.AgentSocket, "GET", "/v1/ids/alerts?after="+strconv.FormatInt(cfg.IDSCursor, 10), nil, &alerts); err != nil || len(alerts) == 0 {
		return false, err
	}
	messages := make([]string, 0, len(alerts))
	for _, alert := range alerts {
		severity := 3
		switch alert.Severity {
		case 1:
			severity = 8
		case 2:
			severity = 6
		}
		messages = append(messages, siem.Event(host, alert.At, version, "suricata."+strconv.FormatInt(alert.SID, 10), alert.Message, severity,
			siem.Field{Key: "externalId", Value: strconv.FormatInt(alert.ID, 10)},
			siem.Field{Key: "src", Value: alert.Src}, siem.Field{Key: "dst", Value: alert.Dst},
			siem.Field{Key: "spt", Value: strconv.Itoa(alert.SrcPort)}, siem.Field{Key: "dpt", Value: strconv.Itoa(alert.DstPort)},
			siem.Field{Key: "proto", Value: alert.Protocol}, siem.Field{Key: "act", Value: alert.Action},
			siem.Field{Key: "deviceInboundInterface", Value: alert.IFace}))
	}
	if err := destination(cfg).Send(ctx, messages); err != nil {
		return false, err
	}
	return len(alerts) == 100, s.Store.AdvanceSIEM(ctx, cfg.Revision, 0, alerts[len(alerts)-1].ID)
}
