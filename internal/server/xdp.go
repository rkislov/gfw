package server

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/xdpguard"
)

type xdpForm struct {
	Interfaces []string `json:"interfaces"`
	Mode       string   `json:"mode"`
	Match      string   `json:"match"`
	Block      []string `json:"block"`
	FeedSHA256 string   `json:"feed_sha256"`
	Exceptions []string `json:"exceptions"`
}
type xdpApply struct {
	ID             string  `json:"id"`
	Revision       int64   `json:"revision"`
	TimeoutSeconds int     `json:"timeout_seconds"`
	Profile        xdpForm `json:"profile"`
}

func (s *Server) xdpRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/xdp/state", s.xdpState)
	api.HandleFunc("POST /api/v1/xdp/apply", s.xdpApply)
	api.HandleFunc("POST /api/v1/xdp/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/xdp/changes/{id}/rollback", s.rollback)
}

func (s *Server) xdpState(w http.ResponseWriter, r *http.Request) {
	state := agent.XDPState{WAN: []string{}, Runtime: []xdpguard.Port{}, History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/xdp", nil, &state); err != nil {
			s.agentError(w, err)
			return
		}
	}
	status, err := s.Store.FeedStatus(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	var available *feed.Entry
	for _, entry := range status.Entries {
		if entry.Name == "ips.txt" {
			available = &entry
			break
		}
	}
	respond(w, 200, struct {
		agent.XDPState
		Feed *feed.Entry `json:"available_feed,omitempty"`
	}{state, available})
}

func (s *Server) xdpApply(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if s.AgentSocket == "" {
		fail(w, 503, "Linux-агент не подключён")
		return
	}
	var in xdpApply
	if decode(w, r, &in) != nil {
		fail(w, 400, "некорректный профиль XDP")
		return
	}
	if !captureID.MatchString(in.ID) || in.Revision < 0 || in.TimeoutSeconds < 30 || in.TimeoutSeconds > 600 {
		fail(w, 422, "нужны ID операции, текущая ревизия и срок 30–600 секунд")
		return
	}
	form := in.Profile
	cfg := xdpguard.Config{Interfaces: form.Interfaces, Mode: form.Mode, Match: form.Match, Block: form.Block}
	if form.FeedSHA256 != "" {
		hash, err := hex.DecodeString(form.FeedSHA256)
		if err != nil || len(hash) != 32 {
			fail(w, 422, "некорректный SHA-256 снимка Security Feed")
			return
		}
		raw, err := s.Store.ReadFeedProjection(r.Context(), "ips.txt", form.FeedSHA256)
		if errors.Is(err, sql.ErrNoRows) {
			var confirmed *feed.Filter
			if e := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/xdp/confirmed-feed", nil, &confirmed); e != nil {
				s.agentError(w, e)
				return
			}
			if confirmed == nil || confirmed.SHA256 != form.FeedSHA256 {
				fail(w, 409, "снимок Security Feed изменился или отсутствует, обновите состояние")
				return
			}
			raw = []byte(strings.Join(confirmed.Values, "\n"))
		} else if err != nil {
			s.internal(w, err)
			return
		}
		cfg.Feed, err = feed.NewFilter("ip", form.FeedSHA256, raw, form.Exceptions)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
	} else if len(form.Exceptions) > 0 {
		fail(w, 422, "исключения применяются только к выбранному снимку Security Feed")
		return
	}
	cfg, err := cfg.Normalize()
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	if !fitsFeedDraft(cfg) {
		fail(w, 422, "профиль XDP превышает размер запроса агента")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "xdp.apply.request:"+in.ID, in.Revision+1); err != nil {
		s.internal(w, err)
		return
	}
	req := agent.XDPRequest{ID: in.ID, Revision: in.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: cfg}
	var result agent.Record
	if err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/xdp/apply", req, &result); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}
