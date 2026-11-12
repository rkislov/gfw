package agent

import (
	"errors"
	"net/http"

	"github.com/rkislov/gfw/internal/vpncred"
)

func (m *Manager) disconnectVPN(protocol string, req vpncred.DisconnectRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return ErrConflict
	}
	switch protocol {
	case "openvpn":
		if m.openvpn != nil {
			for _, instance := range m.openVPNActive().Instances {
				if instance.ID == req.ProfileID && instance.Enabled && instance.Mode == "server" {
					return m.openvpn.Disconnect(instance, *req.SessionID, req.User)
				}
			}
		}
	case "ipsec":
		if m.ipsec != nil {
			for _, tunnel := range m.ipsecActive().Tunnels {
				if tunnel.ID == req.ProfileID && tunnel.Enabled && tunnel.Auth != nil {
					return m.ipsec.Disconnect(tunnel, *req.SessionID, req.User)
				}
			}
		}
	}
	return vpncred.ErrSessionGone
}

func registerVPNDisconnect(mux *http.ServeMux, m *Manager) {
	mux.HandleFunc("POST /v1/vpn/{protocol}/disconnect", func(w http.ResponseWriter, r *http.Request) {
		protocol := r.PathValue("protocol")
		var req vpncred.DisconnectRequest
		if (protocol != "openvpn" && protocol != "ipsec") || jsonRequest(w, r, &req) != nil || !req.Valid() {
			jsonResponse(w, 400, map[string]string{"error": "неверные параметры VPN-сеанса"})
			return
		}
		if m == nil {
			jsonResponse(w, 503, map[string]string{"error": "Linux-агент недоступен"})
			return
		}
		if err := m.disconnectVPN(protocol, req); err != nil {
			status := 502
			if errors.Is(err, vpncred.ErrSessionGone) || errors.Is(err, ErrConflict) {
				status = 409
			}
			jsonResponse(w, status, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, 200, map[string]bool{"ok": true})
	})
}
