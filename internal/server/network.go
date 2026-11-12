package server

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) networkConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadNetwork(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) saveNetwork(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	h := r.Header.Get("If-Match")
	if h == "" {
		fail(w, 428, "нужен If-Match текущей ревизии сети")
		return
	}
	v, err := strconv.Unquote(h)
	if err != nil {
		fail(w, 400, "неверная ревизия сети")
		return
	}
	revision, err := strconv.ParseInt(v, 10, 64)
	if err != nil || revision < 1 {
		fail(w, 400, "неверная ревизия сети")
		return
	}
	var c netconfig.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сети")
		return
	}
	if err = netconfig.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	snap, err := s.Store.SaveNetwork(r.Context(), revision, c)
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
func (s *Server) networkState(w http.ResponseWriter, r *http.Request) {
	v := agent.NetworkState{Confirmed: netconfig.Empty(), History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/network", nil, &v); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, v)
}
func (s *Server) networkPlan(w http.ResponseWriter, r *http.Request) {
	var c netconfig.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сети")
		return
	}
	if err := netconfig.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.AgentSocket == "" {
		respond(w, 200, netconfig.Plan{Files: netconfig.Render(c), Actions: []string{}, Protected: []string{}, Warnings: []string{"Локальный предпросмотр etcnet. Зависимости и состояние Linux не проверены; применение недоступно."}})
		return
	}
	var state agent.NetworkState
	if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/network", nil, &state); err != nil {
		s.agentError(w, err)
		return
	}
	if !state.Enabled {
		respond(w, 200, netconfig.Plan{Files: netconfig.Render(c), Actions: []string{}, Protected: []string{}, Warnings: []string{"Управление сетью в агенте отключено. Это локальный предпросмотр, без проверки состояния Linux."}})
		return
	}
	var v netconfig.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/network/plan", c, &v); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, v)
}
func (s *Server) networkApply(w http.ResponseWriter, r *http.Request) {
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
		fail(w, 400, "неверный JSON применения сети")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(in.ID) || in.TimeoutSeconds < 30 || in.TimeoutSeconds > 600 {
		fail(w, 422, "нужны ID и срок подтверждения 30–600 секунд")
		return
	}
	snap, err := s.Store.ReadNetwork(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия сети изменилась; обновите данные")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "network.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/network/apply", agent.NetworkRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}
