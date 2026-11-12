package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/metrics"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/network"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/tuning"
	"github.com/rkislov/gfw/internal/vpncred"
	"github.com/rkislov/gfw/internal/wireguard"
)

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonRequest(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
func Handler(m *Manager) http.Handler {
	mux := http.NewServeMux()
	registerTraffic(mux, m)
	mux.HandleFunc("GET /v1/firewall/flow", func(w http.ResponseWriter, r *http.Request) {
		state := FlowState{Interfaces: []string{}, Excluded: []FlowExclusion{}}
		if m != nil {
			state = m.FlowState()
		}
		jsonResponse(w, 200, state)
	})
	registerCapture(mux, m)
	registerXDP(mux, m)
	mux.HandleFunc("GET /v1/interfaces", func(w http.ResponseWriter, r *http.Request) {
		v, err := network.Inventory()
		if err != nil {
			jsonResponse(w, 503, map[string]string{"error": "inventory unavailable"})
			return
		}
		jsonResponse(w, 200, v)
	})
	mux.HandleFunc("GET /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		sample, err := metrics.Read()
		if err != nil {
			jsonResponse(w, 503, map[string]string{"error": "system metrics unavailable"})
			return
		}
		jsonResponse(w, 200, sample)
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]bool{"interface_inventory": true, "network_apply": m != nil, "capture": m != nil && m.capture != nil, "xdp": m != nil && m.xdp != nil})
	})
	mux.HandleFunc("GET /v1/firewall", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, State{Enabled: false, History: []Record{}})
			return
		}
		jsonResponse(w, 200, m.State())
	})
	call := func(w http.ResponseWriter, v any, err error) {
		if err != nil {
			status := 422
			if errors.Is(err, ErrConflict) {
				status = 409
			}
			jsonResponse(w, status, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, 200, v)
	}
	enabled := func(w http.ResponseWriter) bool {
		if m == nil {
			jsonResponse(w, 503, map[string]string{"error": "agent apply is disabled"})
			return false
		}
		return true
	}

	mux.HandleFunc("GET /v1/sysctl", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		p, err := tuning.Execute("plan", "")
		call(w, p, err)
	})
	mux.HandleFunc("POST /v1/sysctl/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		action := r.PathValue("action")
		var in struct {
			Token string `json:"token"`
		}
		if action != "apply" && action != "restore" || jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid sysctl request"})
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.j.Pending != nil {
			call(w, nil, ErrConflict)
			return
		}
		p, err := tuning.Execute(action, in.Token)
		call(w, p, err)
	})

	mux.HandleFunc("GET /v1/ids", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, IDSState{})
			return
		}
		jsonResponse(w, 200, m.IDSState())
	})
	mux.HandleFunc("POST /v1/ids/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c ids.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid IDS config"})
			return
		}
		v, e := m.IDSPlan(c)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/ids/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in IDSRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid IDS request"})
			return
		}
		v, e := m.IDSApply(in)
		call(w, v, e)
	})
	mux.HandleFunc("GET /v1/ids/alerts", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if m.ids == nil {
			jsonResponse(w, 200, []ids.Alert{})
			return
		}
		var before int64
		if v := r.URL.Query().Get("before"); v != "" {
			var err error
			before, err = strconv.ParseInt(v, 10, 64)
			if err != nil || before < 1 {
				jsonResponse(w, 400, map[string]string{"error": "invalid alert cursor"})
				return
			}
		}
		v, e := m.ids.Alerts(100, before)
		call(w, v, e)
	})
	mux.HandleFunc("GET /v1/ids/logs", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		lines := []string{}
		if m.ids != nil {
			lines = m.ids.Logs()
		}
		jsonResponse(w, 200, lines)
	})

	mux.HandleFunc("GET /v1/ipsec", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, IPsecState{Confirmed: ipsec.Empty(), Runtime: []ipsec.Status{}, History: []Record{}})
			return
		}
		jsonResponse(w, 200, m.IPsecState())
	})
	mux.HandleFunc("POST /v1/ipsec/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c ipsec.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid IPsec config"})
			return
		}
		v, e := m.IPsecPlan(c)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/ipsec/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in IPsecRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid IPsec request"})
			return
		}
		v, e := m.IPsecApply(in)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/ipsec/materials", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in []ipsec.Material
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid material request"})
			return
		}
		call(w, map[string]bool{"ok": true}, m.IPsecStage(in))
	})
	mux.HandleFunc("POST /v1/ipsec/crl", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in []vpncred.CRLUpdate
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid CRL request"})
			return
		}
		if len(in) > 32 {
			jsonResponse(w, 422, map[string]string{"error": "too many CRLs"})
			return
		}
		call(w, map[string]bool{"ok": true}, m.IPsecRefresh(in))
	})
	mux.HandleFunc("GET /v1/ipsec/logs", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		v, e := m.IPsecLogs()
		call(w, v, e)
	})

	mux.HandleFunc("GET /v1/openvpn", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, OpenVPNState{Confirmed: openvpn.RuntimeEmpty(), Runtime: []openvpn.Status{}, History: []Record{}})
			return
		}
		jsonResponse(w, 200, m.OpenVPNState())
	})
	mux.HandleFunc("POST /v1/openvpn/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c openvpn.RuntimeConfig
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid OpenVPN config"})
			return
		}
		v, e := m.OpenVPNPlan(c)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/openvpn/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in OpenVPNRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid OpenVPN request"})
			return
		}
		v, e := m.OpenVPNApply(in)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/openvpn/materials", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in []openvpn.Material
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid material request"})
			return
		}
		call(w, map[string]bool{"ok": true}, m.OpenVPNStage(in))
	})
	mux.HandleFunc("POST /v1/openvpn/crl", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in []openvpn.CRLUpdate
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid CRL request"})
			return
		}
		if len(in) > 32 {
			jsonResponse(w, 422, map[string]string{"error": "too many CRLs"})
			return
		}
		call(w, map[string]bool{"ok": true}, m.OpenVPNRefresh(in))
	})
	mux.HandleFunc("GET /v1/openvpn/logs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		v, e := m.OpenVPNLogs(r.PathValue("id"))
		call(w, v, e)
	})

	mux.HandleFunc("GET /v1/wireguard", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, WireGuardState{Confirmed: wireguard.Empty(), History: []Record{}, Runtime: []wireguard.TunnelStatus{}})
			return
		}
		jsonResponse(w, 200, m.WireGuardState())
	})
	mux.HandleFunc("POST /v1/wireguard/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c wireguard.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid WireGuard JSON"})
			return
		}
		v, e := m.WireGuardPlan(c)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/wireguard/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in WireGuardRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid WireGuard request"})
			return
		}
		v, e := m.WireGuardApply(in)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/wireguard/keys", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in struct {
			Kind string `json:"kind"`
		}
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid key JSON"})
			return
		}
		v, e := m.WireGuardKey(in.Kind)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/wireguard/export", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in struct {
			TunnelID string `json:"tunnel_id"`
			PeerID   string `json:"peer_id"`
		}
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid export JSON"})
			return
		}
		v, e := m.WireGuardExport(r.Context(), in.TunnelID, in.PeerID)
		call(w, map[string]string{"profile": v}, e)
	})
	mux.HandleFunc("GET /v1/services", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, ServicesState{Confirmed: services.Default(), History: []Record{}})
			return
		}
		jsonResponse(w, 200, m.ServicesState())
	})
	mux.HandleFunc("POST /v1/services/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c services.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid service JSON"})
			return
		}
		v, e := m.ServicesPlan(c)
		call(w, v, e)
	})
	mux.HandleFunc("POST /v1/services/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in ServicesRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid service request"})
			return
		}
		v, e := m.ServicesApply(in)
		call(w, v, e)
	})
	mux.HandleFunc("GET /v1/services/leases", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		v, e := m.ServiceLeases(r.Context())
		call(w, v, e)
	})
	mux.HandleFunc("GET /v1/services/dns-logs", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		call(w, m.ServiceDNSLogs(), nil)
	})
	mux.HandleFunc("POST /v1/firewall/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c policy.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid policy JSON"})
			return
		}
		v, err := m.Plan(c)
		call(w, v, err)
	})
	mux.HandleFunc("POST /v1/firewall/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in ApplyRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid apply JSON"})
			return
		}
		v, err := m.Apply(in)
		call(w, v, err)
	})
	mux.HandleFunc("POST /v1/firewall/{id}/confirm", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		v, err := m.Confirm(r.PathValue("id"))
		call(w, v, err)
	})
	mux.HandleFunc("POST /v1/firewall/{id}/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		v, err := m.Rollback(r.PathValue("id"))
		call(w, v, err)
	})
	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, NetworkState{Confirmed: netconfig.Empty(), History: []Record{}})
			return
		}
		jsonResponse(w, 200, m.NetworkState())
	})
	mux.HandleFunc("POST /v1/network/plan", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var c netconfig.Config
		if jsonRequest(w, r, &c) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid network JSON"})
			return
		}
		v, err := m.NetworkPlan(c)
		call(w, v, err)
	})
	mux.HandleFunc("POST /v1/network/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in NetworkRequest
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "invalid network apply JSON"})
			return
		}
		v, err := m.NetworkApply(in)
		call(w, v, err)
	})
	// Browser requests must go through gfwd's authenticated, CSRF-protected API.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			jsonResponse(w, 403, map[string]string{"error": "browser origin not permitted on agent socket"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}
