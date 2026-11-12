package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/metrics"
)

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	var sample metrics.Sample
	if s.AgentSocket != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		err := agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/metrics", nil, &sample)
		if err != nil {
			fail(w, 503, "Метрики Linux-агента недоступны")
			return
		}
	} else {
		var err error
		sample, err = metrics.Read()
		if err != nil {
			if errors.Is(err, metrics.ErrUnsupported) {
				fail(w, 501, "Метрики доступны на Linux")
			} else {
				fail(w, 503, "Не удалось прочитать метрики узла")
			}
			return
		}
	}
	respond(w, 200, sample)
}
