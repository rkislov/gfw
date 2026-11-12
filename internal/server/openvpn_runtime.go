package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/store"
	"github.com/rkislov/gfw/internal/vpncred"
)

func (s *Server) openvpnRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.ReadOpenVPNRuntime(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) saveOpenVPNRuntime(w http.ResponseWriter, r *http.Request) {
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
	var c openvpn.RuntimeConfig
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	if err = openvpn.ValidateRuntime(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.PKI == nil {
		fail(w, 503, "PKI не подключён")
		return
	}
	for _, i := range c.Instances {
		if i.Enabled {
			if _, err := s.PKI.OpenVPNMaterial(i); err != nil {
				fail(w, 422, err.Error())
				return
			}
		}
	}
	snap, err := s.Store.SaveOpenVPNRuntime(r.Context(), revision, c)
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
func (s *Server) openvpnRuntimeState(w http.ResponseWriter, r *http.Request) {
	v := agent.OpenVPNState{Confirmed: openvpn.RuntimeEmpty(), History: []agent.Record{}}
	if s.AgentSocket != "" {
		if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/openvpn", nil, &v); err != nil {
			v.RuntimeError = "Linux-агент недоступен; доставка CRL будет повторена"
			v.Enabled = false
		}
	}

	s.mu.Lock()
	sync := s.crlSync
	s.mu.Unlock()
	respond(w, 200, map[string]any{"agent": v, "crl_sync": sync})
}
func (s *Server) openvpnRuntimePlan(w http.ResponseWriter, r *http.Request) {
	var c openvpn.RuntimeConfig
	if decode(w, r, &c) != nil {
		fail(w, 400, "неверный JSON сервисов")
		return
	}
	if err := openvpn.ValidateRuntime(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if s.AgentSocket == "" {
		respond(w, 200, openvpn.PreviewRuntime(c))
		return
	}
	var state agent.OpenVPNState
	if err := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/openvpn", nil, &state); err != nil {
		s.agentError(w, err)
		return
	}
	if !state.Enabled {
		respond(w, 200, openvpn.PreviewRuntime(c))
		return
	}
	if err := s.stageOpenVPN(r.Context(), c); err != nil {
		s.agentError(w, err)
		return
	}
	var v openvpn.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/openvpn/plan", c, &v); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, v)
}
func (s *Server) openvpnRuntimeApply(w http.ResponseWriter, r *http.Request) {
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
	snap, err := s.Store.ReadOpenVPNRuntime(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if snap.Revision != in.Revision {
		fail(w, 412, "ревизия сервисов изменилась; обновите данные")
		return
	}
	if err = s.Store.LogAudit(r.Context(), "openvpn.apply.request:"+in.ID, snap.Revision); err != nil {
		s.internal(w, err)
		return
	}
	if err = s.stageOpenVPN(r.Context(), snap.Config); err != nil {
		s.agentError(w, err)
		return
	}
	var result agent.Record
	err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/openvpn/apply", agent.OpenVPNRequest{ID: in.ID, Revision: snap.Revision, TimeoutSeconds: in.TimeoutSeconds, Config: snap.Config}, &result)
	if err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) stageOpenVPN(ctx context.Context, c openvpn.RuntimeConfig) error {
	if s.PKI == nil {
		return &agentclient.Error{Status: 503, Message: "менеджер сертификатов не подключён"}
	}
	if e := s.Store.LogAudit(ctx, "openvpn.material.stage.request", 0); e != nil {
		return e
	}
	all := []openvpn.Material{}
	for _, i := range c.Instances {
		if !i.Enabled {
			continue
		}
		b, e := s.PKI.OpenVPNMaterial(i)
		if e != nil {
			return &agentclient.Error{Status: 422, Message: e.Error()}
		}
		all = append(all, b)
	}
	var out map[string]bool
	return agentclient.Call(ctx, s.AgentSocket, "POST", "/v1/openvpn/materials", all, &out)
}

type CRLSyncStatus struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	Error       string    `json:"error,omitempty"`
}

func (s *Server) SyncOpenVPN(ctx context.Context) error {
	return s.syncVPNCRL(ctx, "openvpn", &s.crlSync, &s.crlSent)
}
func (s *Server) SyncIPsec(ctx context.Context) error {
	return s.syncVPNCRL(ctx, "ipsec", &s.ipsecCRLSync, &s.ipsecCRLSent)
}
func (s *Server) syncVPNCRL(ctx context.Context, kind string, status *CRLSyncStatus, sent *map[string]string) (err error) {
	if s.AgentSocket == "" || s.PKI == nil {
		return nil
	}
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		status.LastAttempt = time.Now().UTC()
		if err != nil {
			status.Error = err.Error()
		} else {
			status.Error = ""
			status.LastSuccess = status.LastAttempt
		}
	}()
	var state struct {
		Enabled     bool     `json:"enabled"`
		RequiredCAs []string `json:"required_cas"`
	}
	if err = agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/"+kind, nil, &state); err != nil {
		return err
	}
	if !state.Enabled {
		return nil
	}
	updates := []vpncred.CRLUpdate{}
	hashes := map[string]string{}
	var problems error
	for _, id := range state.RequiredCAs {
		u, e := s.PKI.OpenVPNCRL(id)
		if e != nil {
			problems = errors.Join(problems, e)
			continue
		}
		hash := sha256.Sum256(u.CRL)
		digest := hex.EncodeToString(hash[:])
		if (*sent)[id] != digest {
			updates = append(updates, u)
			hashes[id] = digest
		}
	}
	if len(updates) > 0 {
		if e := s.Store.LogAudit(ctx, kind+".crl.sync.request", 0); e != nil {
			return e
		}
		var out map[string]bool
		err = agentclient.Call(ctx, s.AgentSocket, "POST", "/v1/"+kind+"/crl", updates, &out)
		if err == nil {
			if *sent == nil {
				*sent = map[string]string{}
			}
			for id, digest := range hashes {
				(*sent)[id] = digest
			}
		}
	}
	return errors.Join(err, problems)
}
func (s *Server) RunVPNCRLSync(ctx context.Context) {
	if s.AgentSocket == "" {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		_ = s.SyncOpenVPN(ctx)
		_ = s.SyncIPsec(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) openvpnRuntimeLogs(w http.ResponseWriter, r *http.Request) {
	if !openvpn.IDPattern.MatchString(r.PathValue("id")) {
		fail(w, 400, "неверный ID экземпляра")
		return
	}
	if s.AgentSocket == "" {
		fail(w, 503, "Linux-агент не подключён")
		return
	}
	var lines []string
	if e := agentclient.Call(r.Context(), s.AgentSocket, "GET", "/v1/openvpn/logs/"+r.PathValue("id"), nil, &lines); e != nil {
		s.agentError(w, e)
		return
	}
	respond(w, 200, lines)
}
