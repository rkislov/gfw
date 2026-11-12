package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/vpncred"
)

func (s *Server) disconnectVPN(w http.ResponseWriter, r *http.Request) {
	protocol := r.PathValue("protocol")
	var req vpncred.DisconnectRequest
	if (protocol != "openvpn" && protocol != "ipsec") || decode(w, r, &req) != nil || !req.Valid() {
		fail(w, 400, "неверные параметры VPN-сеанса")
		return
	}
	actor := requestIdentity(r).Name
	target := fmt.Sprintf("%s:%d:%s", req.ProfileID, *req.SessionID, req.User)
	logEvent := func(ctx context.Context, result string) error {
		return s.Store.LogAuditActor(ctx, actor, "vpn.disconnect."+protocol+"."+result+":"+target, 0)
	}
	if err := logEvent(r.Context(), "request"); err != nil {
		s.internal(w, err)
		return
	}
	// Finish and record the result even if the browser closes after submitting.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	var result struct {
		OK bool `json:"ok"`
	}
	status := http.StatusOK
	if s.AgentSocket == "" {
		status = http.StatusServiceUnavailable
	} else {
		err := agentclient.Call(ctx, s.AgentSocket, "POST", "/v1/vpn/"+protocol+"/disconnect", req, &result)
		if err != nil || !result.OK {
			status = http.StatusBadGateway
			var remote *agentclient.Error
			if errors.As(err, &remote) && remote.Status == http.StatusConflict {
				status = http.StatusConflict
			}
		}
	}
	auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer auditCancel()
	outcome := "success"
	if status != http.StatusOK {
		outcome = "failed"
	}
	if err := logEvent(auditCtx, outcome); err != nil {
		s.internal(w, err)
		return
	}
	switch status {
	case http.StatusOK:
		respond(w, status, result)
	case http.StatusConflict:
		fail(w, status, "сеанс изменился или уже завершён. Обновите список подключений")
	case http.StatusServiceUnavailable:
		fail(w, status, "Linux-агент недоступен")
	default:
		fail(w, status, "агент не подтвердил отключение. Обновите список подключений")
	}
}
