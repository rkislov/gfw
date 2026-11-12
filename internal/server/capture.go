package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/capture"
)

var captureID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Server) captureRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/captures", func(w http.ResponseWriter, r *http.Request) {
		var state capture.Status
		if s.AgentSocket == "" {
			respond(w, 200, capture.Status{Sessions: []capture.Session{}})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		captureReply(w, &state, agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/captures", nil, &state))
	})
	api.HandleFunc("POST /api/v1/captures", func(w http.ResponseWriter, r *http.Request) {
		var c capture.Config
		if decode(w, r, &c) != nil {
			fail(w, 400, "некорректные параметры захвата")
			return
		}
		if _, err := c.Filter(); err != nil {
			fail(w, 422, err.Error())
			return
		}
		id := random()[:32]
		if !s.captureAudit(w, r, "start", id) {
			return
		}
		var result capture.Session
		captureReply(w, &result, agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/captures/"+id, c, &result))
	})
	api.HandleFunc("POST /api/v1/captures/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		s.captureAction(w, r, "stop", "/stop")
	})
	api.HandleFunc("DELETE /api/v1/captures/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.captureAction(w, r, "delete", "")
	})
	api.HandleFunc("GET /api/v1/captures/{id}/file", s.captureDownload)
}

func (s *Server) captureAction(w http.ResponseWriter, r *http.Request, action, suffix string) {
	id := r.PathValue("id")
	if !s.captureAudit(w, r, action, id) {
		return
	}
	var result map[string]bool
	captureReply(w, &result, agentclient.Call(r.Context(), s.AgentSocket, r.Method, "/v1/captures/"+id+suffix, nil, &result))
}

func (s *Server) captureAudit(w http.ResponseWriter, r *http.Request, action, id string) bool {
	if !captureID.MatchString(id) {
		fail(w, 404, "сессия захвата не найдена")
		return false
	}
	if s.AgentSocket == "" {
		fail(w, 503, "Linux-агент не подключён")
		return false
	}
	if err := s.Store.LogAudit(r.Context(), "capture."+action+".request:"+id, 0); err != nil {
		s.internal(w, err)
		return false
	}
	return true
}

func (s *Server) captureDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.captureAudit(w, r, "download", id) {
		return
	}
	upstream, err := agentclient.Open(r.Context(), s.AgentSocket, r.Method, "/v1/captures/"+id+"/file", r.Header)
	if err != nil {
		fail(w, 503, "захват пакетов недоступен")
		return
	}
	defer upstream.Body.Close()
	for _, key := range []string{"Content-Type", "Content-Disposition", "Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"} {
		if value := upstream.Header.Get(key); value != "" {
			w.Header().Set(key, value)
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(upstream.StatusCode)
	_, _ = io.Copy(w, upstream.Body)
}

func captureReply(w http.ResponseWriter, result any, err error) {
	if err == nil {
		respond(w, 200, result)
		return
	}
	var remote *agentclient.Error
	if errors.As(err, &remote) {
		fail(w, remote.Status, remote.Message)
		return
	}
	fail(w, 503, "захват пакетов недоступен")
}
