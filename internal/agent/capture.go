package agent

import (
	"errors"
	"net/http"

	"github.com/rkislov/gfw/internal/capture"
)

func (m *Manager) SetCapture(c *capture.Manager) { m.capture = c }

func registerCapture(mux *http.ServeMux, m *Manager) {
	mux.HandleFunc("GET /v1/captures", func(w http.ResponseWriter, r *http.Request) {
		state := capture.Status{Sessions: []capture.Session{}}
		if m != nil && m.capture != nil {
			state = m.capture.Status()
		}
		jsonResponse(w, http.StatusOK, state)
	})
	withCapture := func(handler func(http.ResponseWriter, *http.Request, *capture.Manager)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if m == nil || m.capture == nil {
				jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "захват пакетов недоступен"})
				return
			}
			handler(w, r, m.capture)
		}
	}
	mux.HandleFunc("POST /v1/captures/{id}", withCapture(func(w http.ResponseWriter, r *http.Request, c *capture.Manager) {
		var in capture.Config
		if jsonRequest(w, r, &in) != nil {
			jsonResponse(w, 400, map[string]string{"error": "некорректные параметры захвата"})
			return
		}
		result, err := c.Start(r.PathValue("id"), in)
		captureResult(w, result, err)
	}))
	mux.HandleFunc("POST /v1/captures/{id}/stop", withCapture(func(w http.ResponseWriter, r *http.Request, c *capture.Manager) {
		captureResult(w, map[string]bool{"ok": true}, c.Stop(r.PathValue("id")))
	}))
	mux.HandleFunc("DELETE /v1/captures/{id}", withCapture(func(w http.ResponseWriter, r *http.Request, c *capture.Manager) {
		captureResult(w, map[string]bool{"ok": true}, c.Remove(r.PathValue("id")))
	}))
	mux.HandleFunc("GET /v1/captures/{id}/file", withCapture(func(w http.ResponseWriter, r *http.Request, c *capture.Manager) {
		file, s, err := c.File(r.PathValue("id"))
		if err != nil {
			captureResult(w, nil, err)
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", `attachment; filename="gfw-`+s.ID+`.pcap"`)
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("ETag", `"`+s.SHA256+`"`)
		http.ServeContent(w, r, "gfw-"+s.ID+".pcap", *s.End, file)
	}))
}

func captureResult(w http.ResponseWriter, data any, err error) {
	if err == nil {
		jsonResponse(w, 200, data)
		return
	}
	status := http.StatusUnprocessableEntity
	switch {
	case errors.Is(err, capture.ErrMissing):
		status = http.StatusNotFound
	case errors.Is(err, capture.ErrActive), errors.Is(err, capture.ErrBusy), errors.Is(err, capture.ErrQuota):
		status = http.StatusConflict
	}
	jsonResponse(w, status, map[string]string{"error": err.Error()})
}
