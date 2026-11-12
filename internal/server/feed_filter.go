package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) stageFeedFilter(w http.ResponseWriter, r *http.Request) {
	consumer := r.PathValue("consumer")
	var kind, file string
	switch consumer {
	case "firewall":
		kind, file = "ip", "ips.txt"
	case "dns":
		kind, file = "domain", "domains.txt"
	default:
		http.NotFound(w, r)
		return
	}
	var in struct {
		Revision   int64    `json:"revision"`
		SHA256     string   `json:"sha256"`
		Exceptions []string `json:"exceptions"`
		Disable    bool     `json:"disable"`
	}
	if decode(w, r, &in) != nil || in.Revision < 1 ||
		(in.Disable && (in.SHA256 != "" || len(in.Exceptions) > 0)) || (!in.Disable && len(in.SHA256) != 64) {
		fail(w, 400, "Нужны ревизия черновика и SHA-256 снимка или явное отключение")
		return
	}
	ctx := r.Context()
	var f *feed.Filter
	if !in.Disable {
		raw, err := s.Store.ReadFeedProjection(ctx, file, in.SHA256)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 409, "Снимок изменился или отсутствует. Обновите данные подписки.")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		f, err = feed.NewFilter(kind, in.SHA256, raw, in.Exceptions)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
	}

	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	var result any
	var err error
	if consumer == "firewall" {
		draft, e := s.Store.Read(ctx)
		if e != nil {
			s.internal(w, e)
			return
		}
		if draft.Revision != in.Revision {
			fail(w, 409, store.ErrConflict.Error())
			return
		}
		draft.Config.SecurityFeed = f
		if e = policy.Validate(draft.Config); e != nil {
			fail(w, 422, e.Error())
			return
		}
		if !fitsFeedDraft(draft.Config) {
			fail(w, 422, "Черновик firewall со списком превышает размер запроса агента")
			return
		}
		result, err = s.Store.Save(ctx, in.Revision, draft.Config)
	} else {
		draft, e := s.Store.ReadServices(ctx)
		if e != nil {
			s.internal(w, e)
			return
		}
		if draft.Revision != in.Revision {
			fail(w, 409, store.ErrConflict.Error())
			return
		}
		draft.Config.DNS.SecurityFeed = f
		if e = services.Validate(draft.Config); e != nil {
			fail(w, 422, e.Error())
			return
		}
		if !fitsFeedDraft(draft.Config) {
			fail(w, 422, "Черновик DNS со списком превышает размер запроса агента")
			return
		}
		result, err = s.Store.SaveServices(ctx, in.Revision, draft.Config)
	}
	if errors.Is(err, store.ErrConflict) {
		fail(w, 409, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	respond(w, 200, result)
}

func fitsFeedDraft(config any) bool {
	body, err := json.Marshal(config)
	// Leave room for change ID, timeout and revision in the agent envelope.
	return err == nil && len(body) <= (2<<20)-1024
}
