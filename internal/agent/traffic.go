package agent

import (
	"encoding/json"
	"net/http"

	"github.com/rkislov/gfw/internal/traffic"
)

func (m *Manager) SetTraffic(c *traffic.Collector) { m.traffic = c }

func registerTraffic(mux *http.ServeMux, m *Manager) {
	if m == nil || m.traffic == nil {
		return
	}
	mux.HandleFunc("GET /v1/traffic/status", func(w http.ResponseWriter, r *http.Request) {
		s, err := m.traffic.Status(r.Context())
		if err != nil {
			jsonResponse(w, 503, map[string]string{"error": "traffic spool unavailable"})
			return
		}
		if nft, ok := m.backend.(NFT); ok {
			s.RateLimited = nft.trafficRateLimited()
		}
		jsonResponse(w, 200, s)
	})
	mux.HandleFunc("GET /v1/traffic/batch", func(w http.ResponseWriter, r *http.Request) {
		b, err := m.traffic.Peek(r.Context())
		if err != nil {
			jsonResponse(w, 503, map[string]string{"error": "traffic spool unavailable"})
			return
		}
		jsonResponse(w, 200, b)
	})
	mux.HandleFunc("POST /v1/traffic/ack", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Cursor int64 `json:"cursor"`
		}
		if jsonRequest(w, r, &in) != nil || in.Cursor < 1 {
			jsonResponse(w, 400, map[string]string{"error": "invalid traffic cursor"})
			return
		}
		if err := m.traffic.Ack(r.Context(), in.Cursor); err != nil {
			jsonResponse(w, 503, map[string]string{"error": "traffic spool unavailable"})
			return
		}
		jsonResponse(w, 200, map[string]bool{"ok": true})
	})
}

type namedCounter struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func (n NFT) namedCounters(table string) (map[string]namedCounter, error) {
	raw, err := n.run("", "-j", "list", "counters", "inet", table)
	if err != nil {
		return nil, err
	}
	var data struct {
		NFTables []struct {
			Counter *namedCounter `json:"counter"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	counts := make(map[string]namedCounter, len(data.NFTables))
	for _, entry := range data.NFTables {
		if entry.Counter != nil {
			counts[entry.Counter.Name] = *entry.Counter
		}
	}
	return counts, nil
}

func (n NFT) trafficRateLimited() *uint64 {
	counts, err := n.namedCounters("gfw")
	if err != nil {
		return nil
	}
	seen, seenOK := counts[traffic.SeenCounter]
	logged, loggedOK := counts[traffic.LoggedCounter]
	if !seenOK || !loggedOK {
		return nil
	}
	limited := max(seen.Packets, logged.Packets) - logged.Packets
	return &limited
}
