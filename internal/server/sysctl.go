package server

import (
	"net/http"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/tuning"
)

func (s *Server) sysctlRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/sysctl", s.sysctl)
	api.HandleFunc("POST /api/v1/sysctl/{action}", s.sysctl)
}

func (s *Server) sysctl(w http.ResponseWriter, r *http.Request) {
	if s.AgentSocket == "" {
		fail(w, 503, "нужен Linux-агент")
		return
	}
	path := "/v1/sysctl"
	var body any
	if r.Method == "POST" {
		action := r.PathValue("action")
		var in struct {
			Token string `json:"token"`
		}
		if action != "apply" && action != "restore" || decode(w, r, &in) != nil {
			fail(w, 400, "некорректная операция sysctl")
			return
		}
		if err := s.Store.LogAuditActor(r.Context(), requestIdentity(r).Name, "sysctl."+action+".request", 0); err != nil {
			s.internal(w, err)
			return
		}
		path += "/" + action
		body = in
	}
	var plan tuning.Plan
	if err := agentclient.Call(r.Context(), s.AgentSocket, r.Method, path, body, &plan); err != nil {
		s.agentError(w, err)
		return
	}
	respond(w, 200, plan)
}
