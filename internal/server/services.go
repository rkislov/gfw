package server

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) servicesConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadServices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) saveServices(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	h := r.Header.Get("If-Match")
	if h == "" {
		fail(w, 428, "нужен If-Match текущей ревизии сервисов")
		return
	}
	v, err := strconv.Unquote(h)
	if err != nil {
		fail(w, 400, "неверная ревизия сервисов")
		return
	}
	revision, err := strconv.ParseInt(v, 10, 64)
	if err != nil || revision < 1 {
		fail(w, 400, "неверная ревизия сервисов")
		return
	}
	var c services.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	draft, err := s.Store.ReadServices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if draft.Revision != revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	c.DNS.SecurityFeed = draft.Config.DNS.SecurityFeed
	if c.DNS.SecurityFeed != nil && !fitsFeedDraft(c) {
		fail(w, 422, "Черновик DNS со списком превышает размер запроса агента")
		return
	}
	if err = services.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	snap, err := s.Store.SaveServices(r.Context(), revision, c)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 412, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) servicesState(w http.ResponseWriter, r *http.Request) {
	v := agent.ServicesState{Confirmed: services.Default(), History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/services", nil, &v); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, v)
}
func (s *Server) servicesPlan(w http.ResponseWriter, r *http.Request) {
	var c services.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	if err := services.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.AgentSocket == "" {
		respond(w, 200, services.Preview(c))
		return
	}
	var state agent.ServicesState
	if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/services", nil, &state); err != nil {
		s.agentError(w, err)
		return
	}
	if !state.Enabled {
		respond(w, 200, services.Preview(c))
		return
	}
	var v services.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/services/plan", c, &v); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, v)
}
func (s *Server) servicesApply(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if s.AgentSocket == "" {
		fail(w, 503, "не подключён Linux-агент")
		return
	}
	var in struct {
		ID             string `json:"id"`
		Revision       int64  `json:"revision"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if decode(w, r, &in) != nil {
		fail(w, 400, "неверный JSON применения сервисов")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(in.ID) || in.TimeoutSeconds < 30 || in.TimeoutSeconds > 600 {
		fail(w, 422, "нужны ID и срок подтверждения 30–600 секунд")
		return
	}
	snap, err := s.Store.ReadServices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия сервисов изменилась; обновите данные")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "services.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/services/apply", agent.ServicesRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) serviceLeases(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		respond(w, 200, []services.Lease{})
		return
	}
	var v []services.Lease
	if e := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/services/leases", nil, &v); e != nil {
		s.agentError(w, e)
		return
	}
	respond(w, 200, v)
}
func (s *Server) serviceDNSLogs(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		respond(w, 200, []any{})
		return
	}
	var v any
	if e := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/services/dns-logs", nil, &v); e != nil {
		s.agentError(w, e)
		return
	}
	respond(w, 200, v)
}
