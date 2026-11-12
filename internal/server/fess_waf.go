package server

import (
	"encoding/json"
	"net/http"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/fess"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) fessWAFCatalog(w http.ResponseWriter, r *http.Request) {
	if s.feed == nil || s.feed.current().Key == "" {
		fail(w, 503, "Подключите подписку Security Feed")
		return
	}
	packs, err := feed.NewClient().WAFCatalog(r.Context(), s.feed.current().Key)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	respond(w, 200, packs)
}

func (s *Server) fessWAFImport(w http.ResponseWriter, r *http.Request) {
	if s.feed == nil || s.feed.current().Key == "" || s.fess == nil {
		fail(w, 503, "Подключите подписку Security Feed")
		return
	}
	var in struct {
		Revision int64  `json:"revision"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		feed.WAFMeta
	}
	if decode(w, r, &in) != nil || in.Revision < 1 {
		fail(w, 400, "Некорректные параметры импорта WAF")
		return
	}
	raw, err := feed.NewClient().WAFPack(r.Context(), s.feed.current().Key, in.ID, in.Version, in.SHA256)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	var document struct {
		Format  string
		Engine  string
		ID      string `json:"pack_id"`
		Version string
		Rules   []fess.Rule
	}
	if json.Unmarshal(raw, &document) != nil || document.Format != "security-feed-waf-v1" ||
		(document.Engine != "fess-native-v1" && document.Engine != "fess-native-v2") ||
		document.ID != in.ID || document.Version != in.Version || len(document.Rules) == 0 {
		fail(w, 422, "Набор WAF несовместим с FESS")
		return
	}
	s.fess.mu.Lock()
	defer s.fess.mu.Unlock()
	draft, err := s.Store.ReadFESS(r.Context(), false)
	if err != nil {
		s.internal(w, err)
		return
	}
	if draft.Revision != in.Revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	for i, site := range draft.Config.Sites {
		if site.Host == in.Host && site.Path == in.Path {
			draft.Config.Sites[i].Pack = &fess.Pack{ID: in.ID, Version: in.Version, SHA256: in.SHA256, Rules: document.Rules}
			draft.Config.Sites[i].UsePack = false
			s.saveFESSDraft(w, r, draft)
			return
		}
	}
	fail(w, 404, "Маршрут отсутствует в черновике")
}
