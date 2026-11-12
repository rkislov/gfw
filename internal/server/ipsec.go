package server

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) ipsecConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadIPsec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) saveIPsec(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	h := r.Header.Get("If-Match")
	if h == "" {
		fail(w, 428, "нужен If-Match текущей ревизии IPsec")
		return
	}
	v, err := strconv.Unquote(h)
	if err != nil {
		fail(w, 400, "неверная ревизия IPsec")
		return
	}
	revision, err := strconv.ParseInt(v, 10, 64)
	if err != nil || revision < 1 {
		fail(w, 400, "неверная ревизия IPsec")
		return
	}
	var c ipsec.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON IPsec")
		return
	}
	if err = ipsec.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.PKI == nil {
		fail(w, 503, "PKI не подключён")
		return
	}
	for _, i := range c.Tunnels {
		if i.Enabled {
			if _, err := s.PKI.IPsecMaterial(i); err != nil {
				fail(w, 422, err.Error())
				return
			}
		}
	}
	snap, err := s.Store.SaveIPsec(r.Context(), revision, c)
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
func (s *Server) ipsecState(w http.ResponseWriter, r *http.Request) {
	v := agent.IPsecState{Confirmed: ipsec.Empty(), History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ipsec", nil, &v); err != nil {
			v.RuntimeError = "Linux-агент недоступен; доставка CRL будет повторена"
			v.Enabled = false
		}
	}

	s.mu.Lock()
	sync := s.ipsecCRLSync
	s.mu.Unlock()
	respond(w, 200, map[string]any{"agent": v, "crl_sync": sync})
}
func (s *Server) ipsecPlan(w http.ResponseWriter, r *http.Request) {
	var c ipsec.Config
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON IPsec")
		return
	}
	if err := ipsec.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.AgentSocket == "" {
		respond(w, 200, ipsec.Preview(c))
		return
	}
	var state agent.IPsecState
	if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ipsec", nil, &state); err != nil {
		s.agentError(w, err)
		return
	}
	if !state.Enabled {
		respond(w, 200, ipsec.Preview(c))
		return
	}
	if err := s.stageIPsec(r.Context(), c); err != nil {
		s.agentError(w, err)
		return
	}
	var v ipsec.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/ipsec/plan", c, &v); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, v)
}
func (s *Server) ipsecApply(w http.ResponseWriter, r *http.Request) {
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
		fail(w, 400, "неверный JSON применения IPsec")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`).MatchString(in.ID) || in.TimeoutSeconds < 30 || in.TimeoutSeconds > 600 {
		fail(w, 422, "нужны ID и срок подтверждения 30–600 секунд")
		return
	}
	snap, err := s.Store.ReadIPsec(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия IPsec изменилась; обновите данные")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "ipsec.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	if err = s.stageIPsec(r.Context(), snap.Config); err != nil {
		s.agentError(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/ipsec/apply", agent.IPsecRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) stageIPsec(ctx context.Context, c ipsec.Config) error {
	if s.PKI == nil {
		return &agentclient.Error{Status: 503, Message: "менеджер сертификатов не подключён"}
	}
	if e := s.Store.LogAudit(ctx, "ipsec.material.stage.request", 0); e != nil {
		return e
	}
	all := []ipsec.Material{}
	for _, i := range c.Tunnels {
		if !i.Enabled {
			continue
		}
		b, e := s.PKI.IPsecMaterial(i)
		if e != nil {
			return &agentclient.Error{Status: 422, Message: e.Error()}
		}
		all = append(all, b)
	}
	var out map[string]bool
	return agentclient.Call(ctx, s.AgentSocket, "POST", "/v1/ipsec/materials", all, &out)
}

func (s *Server) ipsecLogs(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		fail(w, 503, "Linux-агент не подключён")
		return
	}
	var lines []string
	if e := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/ipsec/logs", nil, &lines); e != nil {
		s.agentError(w, e)
		return
	}
	respond(w, 200, lines)
}
