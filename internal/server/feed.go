package server

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/store"
	"github.com/rkislov/gfw/internal/vpncred"
)

type feedSettings struct {
	Revision int64  `json:"revision"`
	Key      string `json:"key,omitempty"`
	Hours    int    `json:"interval_hours"`
}

type feedSource interface {
	Catalog(context.Context, string) (feed.Entry, error)
	Download(context.Context, string) ([]feed.Entry, error)
}

type feedManager struct {
	mu       sync.Mutex
	refresh  sync.Mutex
	settings feedSettings
	vault    *vpncred.Vault
	client   feedSource
}

const feedSettingsFile = "subscription"

func (s *Server) EnableFeed(dir string) error {
	vault, err := vpncred.OpenVault(dir)
	if err != nil {
		return err
	}
	m := &feedManager{
		vault:    vault,
		settings: feedSettings{Revision: 1},
		client:   feed.NewClient(),
	}
	if err = vault.Get(feedSettingsFile, &m.settings); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.feed = m
	return nil
}

func (s *Server) feedRoutes(api *http.ServeMux) {
	if s.feed == nil {
		api.HandleFunc("/api/v1/feed", feedUnavailable)
		api.HandleFunc("/api/v1/feed/", feedUnavailable)
		return
	}
	api.HandleFunc("GET /api/v1/feed", s.feedStatus)
	api.HandleFunc("PUT /api/v1/feed", s.feedSave)
	api.HandleFunc("POST /api/v1/feed/check", s.feedCheck)
	api.HandleFunc("POST /api/v1/feed/refresh", s.feedRefresh)
	api.HandleFunc("GET /api/v1/feed/files/{name}", s.feedFile)
	api.HandleFunc("POST /api/v1/feed/consumers/{consumer}", s.stageFeedFilter)
}

func feedUnavailable(w http.ResponseWriter, _ *http.Request) {
	fail(w, 503, "Хранилище подписки недоступно")
}

func (m *feedManager) current() feedSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

func (s *Server) feedStatus(w http.ResponseWriter, r *http.Request) {
	settings := s.feed.current()
	status, err := s.Store.FeedStatus(r.Context())
	if err != nil {
		fail(w, 500, "Не удалось прочитать состояние подписки")
		return
	}
	success, _ := time.Parse(time.RFC3339Nano, status.SuccessAt)
	staleAfter := max(24, settings.Hours*2)
	respond(w, 200, struct {
		store.FeedStatus
		Origin   string `json:"origin"`
		HasKey   bool   `json:"has_key"`
		Revision int64  `json:"revision"`
		Hours    int    `json:"interval_hours"`
		Stale    bool   `json:"stale"`
	}{status, feed.Origin, settings.Key != "", settings.Revision, settings.Hours,
		!success.IsZero() && time.Since(success) > time.Duration(staleAfter)*time.Hour})
}

func (s *Server) feedSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		feedSettings
		RemoveKey bool `json:"remove_key"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, "Некорректные настройки подписки")
		return
	}
	in.Key = strings.TrimSpace(in.Key)
	if in.Hours < 0 || in.Hours > 168 || len(in.Key) > 512 ||
		strings.ContainsFunc(in.Key, func(c rune) bool { return c < 33 || c > 126 }) ||
		(in.RemoveKey && in.Key != "") {
		fail(w, 400, "Укажите корректный API-ключ и интервал от 0 до 168 часов")
		return
	}
	m := s.feed
	m.mu.Lock()
	if in.Revision != m.settings.Revision {
		m.mu.Unlock()
		fail(w, 409, store.ErrConflict.Error())
		return
	}
	if in.Key == "" && !in.RemoveKey {
		in.Key = m.settings.Key
	}
	if in.Key == "" && in.Hours != 0 {
		m.mu.Unlock()
		fail(w, 400, "Для обновления по расписанию нужен API-ключ")
		return
	}
	in.Revision++
	if err := m.vault.Put(feedSettingsFile, in.feedSettings); err != nil {
		m.mu.Unlock()
		fail(w, 500, "Не удалось сохранить настройки подписки")
		return
	}
	m.settings = in.feedSettings
	m.mu.Unlock()
	_ = s.Store.LogAudit(r.Context(), "feed.settings.save", in.Revision)
	s.feedStatus(w, r)
}

func (s *Server) feedCheck(w http.ResponseWriter, r *http.Request) {
	settings := s.feed.current()
	if settings.Key == "" {
		fail(w, 400, "Сначала сохраните API-ключ")
		return
	}
	if _, err := s.feed.client.Catalog(r.Context(), settings.Key); err != nil {
		fail(w, 502, err.Error())
		return
	}
	respond(w, 200, map[string]bool{"accessible": true})
}

var (
	errFeedBusy  = errors.New("Обновление уже выполняется")
	errFeedNoKey = errors.New("Сначала сохраните API-ключ")
)

func (s *Server) refreshFeed(ctx context.Context, actor string, acceptShrink bool) error {
	m := s.feed
	if !m.refresh.TryLock() {
		return errFeedBusy
	}
	defer m.refresh.Unlock()
	settings := m.current()
	if settings.Key == "" || (actor == "system" && settings.Hours == 0) {
		return errFeedNoKey
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	entries, err := m.client.Download(ctx, settings.Key)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings.Revision != settings.Revision {
		return store.ErrConflict
	}
	if ctx.Err() != nil {
		// Allow the attempt to be recorded if its own fetch deadline expired.
		err = errors.New("Истекло время ожидания обновления Security Feed")
	}
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer saveCancel()
	status, e := s.Store.FeedStatus(saveCtx)
	if e != nil {
		return errors.New("Не удалось проверить предыдущий снимок")
	}
	if err == nil && !acceptShrink {
		for _, prior := range status.Entries {
			for _, entry := range entries {
				if entry.Name == prior.Name && prior.Count >= 100 && entry.Count < prior.Count/10 {
					err = errors.New(entry.Name + ": резкое уменьшение числа записей, сохранён предыдущий снимок")
				}
			}
		}
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	if e = s.Store.RecordFeedAttempt(saveCtx, settings.Revision, actor, message, entries); e != nil {
		return errors.New("Не удалось записать результат обновления")
	}
	return err
}

func (s *Server) feedRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AcceptShrink bool `json:"accept_shrink"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, "Некорректные параметры обновления")
		return
	}
	if err := s.refreshFeed(r.Context(), "admin", in.AcceptShrink); err != nil {
		code := 502
		switch {
		case errors.Is(err, errFeedBusy), errors.Is(err, store.ErrConflict):
			code = 409
		case errors.Is(err, errFeedNoKey):
			code = 400
		}
		fail(w, code, err.Error())
		return
	}
	s.feedStatus(w, r)
}

func (s *Server) feedFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	switch name {
	case "catalog.json", "ips.txt", "domains.txt", "iocs.json":
	default:
		http.NotFound(w, r)
		return
	}
	normalized := r.URL.Query().Get("normalized") == "1"
	raw, err := s.Store.ReadFeedFile(r.Context(), name, normalized)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "Файл ещё не загружен")
		return
	}
	if err != nil {
		fail(w, 500, "Не удалось прочитать файл")
		return
	}
	if normalized {
		name = "normalized-" + name
	}
	if err = s.Store.LogAudit(r.Context(), "feed.download."+name, 0); err != nil {
		fail(w, 500, "Не удалось записать действие в аудит")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(raw)
}

func (s *Server) RunFeed(ctx context.Context) {
	if s.feed == nil {
		return
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		settings := s.feed.current()
		if settings.Key != "" && settings.Hours > 0 {
			status, err := s.Store.FeedStatus(ctx)
			if err == nil {
				delay := time.Duration(settings.Hours) * time.Hour
				if status.Error != "" {
					delay = min(delay, 15*time.Minute)
				}
				last, _ := time.Parse(time.RFC3339Nano, status.AttemptAt)
				if time.Since(last) >= delay {
					_ = s.refreshFeed(ctx, "system", false)
				}
			}
		}
		timer.Reset(time.Minute + time.Duration(rand.IntN(15))*time.Second)
	}
}
