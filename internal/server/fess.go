package server

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rkislov/gfw/internal/fess"
	"github.com/rkislov/gfw/internal/store"
)

type fessManager struct {
	events     chan fess.Event
	stop       chan struct{}
	done       chan struct{}
	dropped    atomic.Uint64
	mu         sync.Mutex
	runtime    *fess.Runtime
	confirmed  store.FESSSnapshot
	live       *fess.Publication
	pending    *fessPending
	startError string
}

type fessPending struct {
	ID       string             `json:"id"`
	Deadline time.Time          `json:"deadline"`
	Draft    store.FESSSnapshot `json:"-"`
	Timer    *time.Timer        `json:"-"`
}

func (s *Server) EnableFESS(ctx context.Context, reserved ...string) {
	m := &fessManager{events: make(chan fess.Event, 256), stop: make(chan struct{}), done: make(chan struct{})}
	m.runtime = fess.New(s.PKI.SiteCertificate, func(event fess.Event) {
		select {
		case m.events <- event:
		default:
			m.dropped.Add(1)
		}
	}, reserved...)
	go s.writeFESSJournal(m)
	s.fess = m
	var err error
	m.confirmed, err = s.Store.ReadFESS(ctx, true)
	if err == nil {
		m.live, err = m.runtime.Prepare(m.confirmed.Config)
	}
	if err == nil {
		err = m.runtime.Set(m.live)
	}
	if err != nil {
		m.startError = err.Error()
	}
}

func (s *Server) CloseFESS() {
	m := s.fess
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		m.pending.Timer.Stop()
		m.pending = nil
	}
	_ = m.runtime.Set(nil)
	m.runtime.Release()
	close(m.stop)
	<-m.done
}

func (s *Server) fessRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/fess/config", s.fessConfig)
	api.HandleFunc("PUT /api/v1/fess/config", s.saveFESS)
	api.HandleFunc("GET /api/v1/fess/state", s.fessState)
	api.HandleFunc("POST /api/v1/fess/plan", s.fessPlan)
	api.HandleFunc("POST /api/v1/fess/apply", s.fessApply)
	api.HandleFunc("POST /api/v1/fess/changes/{id}/{action}", s.resolveFESS)
	api.HandleFunc("GET /api/v1/fess/events", func(w http.ResponseWriter, r *http.Request) {
		if s.fess == nil {
			fail(w, 503, "FESS недоступен")
			return
		}
		events, err := s.Store.FESSEvents(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		respond(w, 200, events)
	})
	api.HandleFunc("GET /api/v1/fess/waf/catalog", s.fessWAFCatalog)
	api.HandleFunc("POST /api/v1/fess/waf/import", s.fessWAFImport)
}

func (s *Server) fessConfig(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.ReadFESS(r.Context(), false)
	if err != nil {
		s.internal(w, err)
		return
	}
	respond(w, 200, v)
}

func (s *Server) saveFESS(w http.ResponseWriter, r *http.Request) {
	var v store.FESSSnapshot
	if decode(w, r, &v) != nil || v.Revision < 1 {
		fail(w, 400, "Некорректный черновик FESS")
		return
	}
	m := s.fess
	if m == nil {
		fail(w, 503, "FESS недоступен")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, err := s.Store.ReadFESS(r.Context(), false)
	if err != nil {
		s.internal(w, err)
		return
	}
	packs := map[string]*fess.Pack{}
	for _, site := range old.Config.Sites {
		packs[site.Host+site.Path] = site.Pack
	}
	for _, site := range v.Config.Sites {
		if site.Pack != nil && !reflect.DeepEqual(site.Pack, packs[site.Host+site.Path]) {
			fail(w, 422, "Импортируйте набор WAF из каталога Security Feed")
			return
		}
	}
	s.saveFESSDraft(w, r, v)
}

func (s *Server) saveFESSDraft(w http.ResponseWriter, r *http.Request, v store.FESSSnapshot) {
	if err := fess.Validate(v.Config); err != nil {
		fail(w, 422, err.Error())
		return
	}
	v, err := s.Store.SaveFESS(r.Context(), v, false)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 412, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	respond(w, 200, v)
}

func (s *Server) fessState(w http.ResponseWriter, _ *http.Request) {
	m := s.fess
	if m == nil {
		fail(w, 503, "FESS недоступен")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	active := m.confirmed.Config
	if m.pending != nil {
		active = m.pending.Draft.Config
	}
	respond(w, 200, map[string]any{"enabled": active.Enabled && m.startError == "", "listen": active.Listen,
		"tls": active.TLS, "revision": m.confirmed.Revision, "pending": m.pending, "error": m.startError, "dropped_events": m.dropped.Load()})
}

func (s *Server) fessPlan(w http.ResponseWriter, r *http.Request) {
	if s.fess == nil {
		fail(w, 503, "FESS недоступен")
		return
	}
	v, err := s.Store.ReadFESS(r.Context(), false)
	if err != nil {
		s.internal(w, err)
		return
	}
	publication, err := s.fess.runtime.Prepare(v.Config)
	if err == nil {
		err = s.fess.runtime.CheckBind(publication)
	}
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	respond(w, 200, v)
}

func (s *Server) fessApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision int64 `json:"revision"`
		Timeout  int   `json:"timeout_seconds"`
	}
	if decode(w, r, &req) != nil || req.Timeout < 30 || req.Timeout > 600 {
		fail(w, 400, "Укажите ревизию и время подтверждения 30–600 секунд")
		return
	}
	m := s.fess
	if m == nil {
		fail(w, 503, "FESS недоступен")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		fail(w, 409, "Дождитесь завершения изменений FESS")
		return
	}
	v, err := s.Store.ReadFESS(r.Context(), false)
	if err != nil {
		s.internal(w, err)
		return
	}
	if v.Revision != req.Revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	pub, err := m.runtime.Prepare(v.Config)
	if err == nil {
		err = m.runtime.Set(pub)
	}
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	p := &fessPending{ID: random(), Deadline: time.Now().Add(time.Duration(req.Timeout) * time.Second), Draft: v}
	m.pending = p
	p.Timer = time.AfterFunc(time.Until(p.Deadline), func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending == p {
			m.rollback()
		}
	})
	m.startError = ""
	respond(w, 200, p)
}

func (m *fessManager) rollback() {
	m.pending.Timer.Stop()
	m.pending = nil
	if err := m.runtime.Set(m.live); err != nil {
		m.startError = err.Error()
	} else {
		m.startError = ""
	}
	m.runtime.Release()
}

func (s *Server) resolveFESS(w http.ResponseWriter, r *http.Request) {
	m := s.fess
	if m == nil {
		fail(w, 503, "FESS недоступен")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.pending
	if p == nil || p.ID != r.PathValue("id") {
		fail(w, 409, "Изменение FESS не ожидает подтверждения")
		return
	}
	if !time.Now().Before(p.Deadline) {
		m.rollback()
		fail(w, 409, "Срок подтверждения истёк")
		return
	}
	switch r.PathValue("action") {
	case "rollback":
		m.rollback()
	case "confirm":
		pub, err := m.runtime.Prepare(p.Draft.Config)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
		if !time.Now().Before(p.Deadline) {
			m.rollback()
			fail(w, 409, "Срок подтверждения истёк")
			return
		}
		if _, err = s.Store.SaveFESS(r.Context(), p.Draft, true); err != nil {
			s.internal(w, err)
			return
		}
		p.Timer.Stop()
		m.confirmed, m.pending, m.live = p.Draft, nil, pub
		m.runtime.Release()
	default:
		http.NotFound(w, r)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func (s *Server) writeFESSJournal(m *fessManager) {
	defer close(m.done)
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	batch := make([]fess.Event, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := s.Store.WriteFESSEvents(ctx, batch); err != nil {
			m.dropped.Add(uint64(len(batch)))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case event := <-m.events:
			batch = append(batch, event)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-timer.C:
			flush()
		case <-m.stop:
			for len(m.events) > 0 && len(batch) < 256 {
				batch = append(batch, <-m.events)
			}
			flush()
			return
		}
	}
}
