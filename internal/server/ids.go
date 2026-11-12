package server

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) idsRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/ids/config", s.idsConfig)
	api.HandleFunc("POST /api/v1/ids/file-ioc/scan", s.scanFileIOC)
	api.HandleFunc("POST /api/v1/ids/file-ioc/stage", s.stageFileIOC)
	api.HandleFunc("PUT /api/v1/ids/config", s.saveIDS)
	api.HandleFunc("GET /api/v1/ids/state", s.idsState)
	api.HandleFunc("POST /api/v1/ids/plan", s.idsPlan)
	api.HandleFunc("POST /api/v1/ids/apply", s.idsApply)
	api.HandleFunc("POST /api/v1/ids/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/ids/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/ids/alerts", s.idsAlerts)
	api.HandleFunc("GET /api/v1/ids/logs", s.idsLogs)
}

func (s *Server) idsConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadIDS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	respondIDS(w, snap)
}

func respondIDS(w http.ResponseWriter, snap store.IDSSnapshot) {
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}

func (s *Server) saveIDS(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("If-Match")
	if header == "" {
		fail(w, 428, "нужна ревизия черновика IDS в If-Match")
		return
	}
	raw, err := strconv.Unquote(header)
	if err != nil {
		fail(w, 400, "неверная ревизия IDS")
		return
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 1 {
		fail(w, 400, "неверная ревизия IDS")
		return
	}
	var c ids.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "некорректный JSON настроек IDS")
		return
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	old, err := s.Store.ReadIDS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if old.Revision != revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	c.FileIOC = old.Config.FileIOC
	if err = ids.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if !fitsFeedDraft(c) {
		fail(w, 422, "Черновик превышает размер запроса агента")
		return
	}
	snap, err := s.Store.SaveIDS(r.Context(), revision, c)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 412, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	respondIDS(w, snap)
}

func (s *Server) idsState(w http.ResponseWriter, r *http.Request) {
	var state agent.IDSState
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ids", nil, &state); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, state)
}

func (s *Server) idsPlan(w http.ResponseWriter, r *http.Request) {
	var c ids.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "некорректный JSON настроек IDS")
		return
	}
	draft, err := s.Store.ReadIDS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	c.FileIOC = draft.Config.FileIOC
	if err := ids.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	plan := ids.Preview(c)
	if s.AgentSocket != "" {
		var state agent.IDSState
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ids", nil, &state); err != nil {
			s.agentError(w, err)
			return
		}
		if state.Enabled {
			if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/ids/plan", c, &plan); err != nil {
				s.agentError(w, err)
				return
			}
		}
	}
	if !plan.Checked {
		plan.Warnings = append(plan.Warnings, "Для проверки правил нужен Suricata на Linux-агенте.")
	}
	respond(w, 200, plan)
}

var idsID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

func (s *Server) idsApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string `json:"id"`
		Revision       int64  `json:"revision"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if decode(w, r, &req) != nil || !idsID.MatchString(req.ID) || req.Revision < 1 ||
		req.TimeoutSeconds < 30 || req.TimeoutSeconds > 600 {
		fail(w, 400, "нужны ID операции, ревизия и срок подтверждения 30–600 секунд")
		return
	}
	if s.AgentSocket == "" {
		fail(w, 503, "не подключён Linux-агент")
		return
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	snap, err := s.Store.ReadIDS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != req.Revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	if err = s.Store.LogAudit(r.Context(), "ids.apply.request:"+req.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	var out agent.Record
	if err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/ids/apply", agent.IDSRequest{
		ID: req.ID, Revision: req.Revision, TimeoutSeconds: req.TimeoutSeconds, Config: snap.Config,
	}, &out); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, out)
}

func (s *Server) idsAlerts(w http.ResponseWriter, r *http.Request) {
	path := "/v1/ids/alerts"
	if cursor := r.URL.Query().Get("before"); cursor != "" {
		n, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || n < 1 {
			fail(w, 400, "некорректная граница журнала")
			return
		}
		path += "?before=" + strconv.FormatInt(n, 10)
	}
	alerts := []ids.Alert{}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", path, nil, &alerts); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, alerts)
}

func (s *Server) idsLogs(w http.ResponseWriter, r *http.Request) {
	lines := []string{}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ids/logs", nil, &lines); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, lines)
}
