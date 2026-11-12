package server

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
)

func (s *Server) agentState(r *http.Request) (agent.State, error) {
	state := agent.State{History: []agent.Record{}}
	if s.AgentSocket == "" {
		return state, nil
	}
	err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/firewall", nil, &state)
	return state, err
}
func (s *Server) agentError(w http.ResponseWriter, err error) {
	var remote *agentclient.Error
	if errors.As(err, &remote) {
		fail(w, remote.Status, remote.Message)
		return
	}
	fail(w, 503, "Linux-агент недоступен; проверьте состояние операции после восстановления связи")
}
func (s *Server) changeState(w http.ResponseWriter, r *http.Request) {
	state, err := s.agentState(r)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, state)
}
func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
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
		fail(w, 400, "некорректный JSON применения")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(in.ID) || in.TimeoutSeconds < 30 || in.TimeoutSeconds > 600 {
		fail(w, 422, "нужен ID операции и срок подтверждения 30–600 секунд")
		return
	}
	snap, err := s.Store.Read(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия черновика изменилась; обновите данные")
		return
	}
	// Audit intent is durable before any privileged action is dispatched. The
	// agent journal is authoritative for outcomes, including autonomous rollback.
	if err = s.Store.LogAudit(r.Context(), "firewall.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/firewall/apply", agent.ApplyRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}
func (s *Server) confirm(w http.ResponseWriter, r *http.Request)  { s.resolve(w, r, "confirm") }
func (s *Server) rollback(w http.ResponseWriter, r *http.Request) { s.resolve(w, r, "rollback") }
func (s *Server) resolve(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(id) {
		fail(w, 400, "некорректный ID операции")
		return
	}
	if s.AgentSocket == "" {
		fail(w, 503, "не подключён Linux-агент")
		return
	}
	kind := "firewall"
	if strings.HasPrefix(r.URL.Path, "/api/v1/xdp/") {
		kind = "xdp"
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/ids/") {
		kind = "ids"
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/ipsec/") {
		kind = "ipsec"
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/openvpn/") {
		kind = "openvpn"
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/wireguard/") {
		kind = "wireguard"
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/network/") {
		kind = "network"
	} else if strings.HasPrefix(r.URL.Path, "/api/v1/services/") {
		kind = "services"
	}
	if err := s.Store.LogAudit(r.Context(), kind+"."+action+".request:"+id, 0); err != nil {
		s.internal(w, err)
		return
	}
	var result agent.Record
	err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/firewall/"+id+"/"+action, nil, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) flowState(w http.ResponseWriter, r *http.Request) {
	state := agent.FlowState{Interfaces: []string{}, Excluded: []agent.FlowExclusion{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/firewall/flow", nil, &state); err != nil {
			s.agentError(w, err)
			return
		}
	}
	respond(w, 200, state)
}
