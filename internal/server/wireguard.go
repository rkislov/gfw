package server

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/store"
	"github.com/rkislov/gfw/internal/wireguard"
)

func (s *Server) wireguardConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadWireGuard(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) saveWireGuard(w http.ResponseWriter, r *http.Request) {
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
	var c wireguard.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	if err = wireguard.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	snap, err := s.Store.SaveWireGuard(r.Context(), revision, c)
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
func (s *Server) wireguardState(w http.ResponseWriter, r *http.Request) {
	v := agent.WireGuardState{Confirmed: wireguard.Empty(), History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/wireguard", nil, &v); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, v)
}
func (s *Server) wireguardPlan(w http.ResponseWriter, r *http.Request) {
	var c wireguard.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	if err := wireguard.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.AgentSocket == "" {
		respond(w, 200, wireguard.Preview(c))
		return
	}
	var state agent.WireGuardState
	if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/wireguard", nil, &state); err != nil {
		s.agentError(w, err)
		return
	}
	if !state.Enabled {
		respond(w, 200, wireguard.Preview(c))
		return
	}
	var v wireguard.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/wireguard/plan", c, &v); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, v)
}
func (s *Server) wireguardApply(w http.ResponseWriter, r *http.Request) {
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
	snap, err := s.Store.ReadWireGuard(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия сервисов изменилась; обновите данные")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "wireguard.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/wireguard/apply", agent.WireGuardRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) wireGuardKey(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		fail(w, 503, "нужен Linux-агент WireGuard")
		return
	}
	var in struct {
		Kind string `json:"kind"`
	}
	if decode(w, r, &in) != nil {
		fail(w, 400, "неверный JSON ключа")
		return
	}
	if e := s.Store.LogAudit(r.Context(), "wireguard.key.create.request:"+in.Kind, 0); e != nil {
		s.internal(w, e)
		return
	}
	var v wireguard.KeyInfo
	if e := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/wireguard/keys", in, &v); e != nil {
		s.agentError(w, e)
		return
	}
	respond(w, 200, v)
}
func (s *Server) wireGuardExport(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		fail(w, 503, "нужен Linux-агент WireGuard")
		return
	}
	var in struct {
		TunnelID string `json:"tunnel_id"`
		PeerID   string `json:"peer_id"`
	}
	if decode(w, r, &in) != nil {
		fail(w, 400, "неверный JSON экспорта")
		return
	}
	if e := s.Store.LogAudit(r.Context(), "wireguard.client.private_export.request:"+in.TunnelID+":"+in.PeerID, 0); e != nil {
		s.internal(w, e)
		return
	}
	var v struct {
		Profile string `json:"profile"`
	}
	if e := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/wireguard/export", in, &v); e != nil {
		s.agentError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="gfw-wireguard.conf"`)
	_, _ = w.Write([]byte(v.Profile))
}
