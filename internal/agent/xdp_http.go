package agent

import (
	"errors"
	"net/http"

	"github.com/rkislov/gfw/internal/xdpguard"
)

func registerXDP(mux *http.ServeMux, m *Manager) {
	mux.HandleFunc("GET /v1/xdp", func(w http.ResponseWriter, r *http.Request) {
		state := XDPState{WAN: []string{}, Runtime: []xdpguard.Port{}, History: []Record{}}
		if m != nil {
			state = m.XDPState()
		}
		jsonResponse(w, http.StatusOK, state)
	})
	mux.HandleFunc("GET /v1/xdp/confirmed-feed", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 200, nil)
			return
		}
		m.mu.Lock()
		f := m.xdpConfig().Feed
		m.mu.Unlock()
		jsonResponse(w, 200, f)
	})
	mux.HandleFunc("POST /v1/xdp/apply", func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			jsonResponse(w, 503, map[string]string{"error": "Linux-агент недоступен"})
			return
		}
		var req XDPRequest
		if jsonRequest(w, r, &req) != nil {
			jsonResponse(w, 400, map[string]string{"error": "некорректный профиль XDP"})
			return
		}
		record, err := m.XDPApply(req)
		if err != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(err, ErrConflict) {
				status = http.StatusConflict
			}
			jsonResponse(w, status, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, 200, record)
	})
}
