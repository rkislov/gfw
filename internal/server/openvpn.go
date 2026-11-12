package server

import (
	"database/sql"
	"errors"
	"net/http"
	"reflect"
	"strconv"

	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) openVPNRoutes(mux *http.ServeMux) {
	ready := func(w http.ResponseWriter) bool {
		if s.PKI == nil {
			fail(w, 503, "менеджер сертификатов не подключён")
			return false
		}
		return true
	}
	issue := func(w http.ResponseWriter, e error) {
		if errors.Is(e, sql.ErrNoRows) {
			fail(w, 422, "сертификат не найден")
		} else {
			fail(w, 422, e.Error())
		}
	}
	mux.HandleFunc("GET /api/v1/openvpn/config", func(w http.ResponseWriter, r *http.Request) {
		snap, e := s.Store.ReadOpenVPN(r.Context())
		if e != nil {
			s.internal(w, e)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
		respond(w, 200, snap)
	})
	mux.HandleFunc("PUT /api/v1/openvpn/config", func(w http.ResponseWriter, r *http.Request) {
		s.changeMu.Lock()
		defer s.changeMu.Unlock()
		if !ready(w) {
			return
		}
		h := r.Header.Get("If-Match")
		if h == "" {
			fail(w, 428, "нужен If-Match текущей ревизии профилей")
			return
		}
		v, e := strconv.Unquote(h)
		if e != nil {
			fail(w, 400, "неверная ревизия профилей")
			return
		}
		revision, e := strconv.ParseInt(v, 10, 64)
		if e != nil || revision < 1 {
			fail(w, 400, "неверная ревизия профилей")
			return
		}
		var c openvpn.Config
		if decode(w, r, &c) != nil {
			fail(w, 400, "неверный JSON OpenVPN")
			return
		}
		if e = openvpn.Validate(c); e != nil {
			issue(w, e)
			return
		}
		old, e := s.Store.ReadOpenVPN(r.Context())
		if e != nil {
			s.internal(w, e)
			return
		}
		if old.Revision != revision {
			fail(w, 412, "профили изменились; обновите данные")
			return
		}
		// An expired/revoked, unchanged profile must not prevent deleting or
		// repairing other entries. New/changed profiles must be valid now.
		for _, p := range c.Profiles {
			unchanged := false
			for _, previous := range old.Config.Profiles {
				if reflect.DeepEqual(p, previous) {
					unchanged = true
					break
				}
			}
			if !unchanged {
				if _, e = s.PKI.CheckOpenVPN(p); e != nil {
					issue(w, e)
					return
				}
			}
		}
		snap, e := s.Store.SaveOpenVPN(r.Context(), revision, c)
		if errors.Is(e, store.ErrConflict) {
			fail(w, 412, e.Error())
			return
		}
		if e != nil {
			s.internal(w, e)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
		respond(w, 200, snap)
	})
	mux.HandleFunc("POST /api/v1/openvpn/check", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var p openvpn.Profile
		if decode(w, r, &p) != nil {
			fail(w, 400, "неверный JSON профиля")
			return
		}
		v, e := s.PKI.CheckOpenVPN(p)
		if e != nil {
			issue(w, e)
			return
		}
		respond(w, 200, map[string]any{"identity": v, "warnings": []string{"Выдача клиентского файла не изменяет работающие экземпляры OpenVPN.", "Профиль требует OpenVPN 2.6+ и закрепляет конкретный серверный сертификат SHA256.", "Маршруты и DNS от сервера игнорируются. Используются только явно заданные настройки профиля.", "Отзыв запрещает новые экспорты. Управляемым экземплярам CRL доставляется автоматически с перезапуском; внешним серверам требуется ручное обновление."}})
	})
	mux.HandleFunc("GET /api/v1/openvpn/state", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		snap, e := s.Store.ReadOpenVPN(r.Context())
		if e != nil {
			s.internal(w, e)
			return
		}
		statuses := []map[string]any{}
		for _, p := range snap.Config.Profiles {
			identity, e := s.PKI.CheckOpenVPN(p)
			status := map[string]any{"id": p.ID, "can_export": e == nil}
			if e != nil {
				if errors.Is(e, sql.ErrNoRows) {
					status["error"] = "сертификат не найден"
				} else {
					status["error"] = e.Error()
				}
			} else {
				status["identity"] = identity
			}
			statuses = append(statuses, status)
		}
		respond(w, 200, map[string]any{"mode": "profiles", "apply_enabled": false, "profiles": statuses})
	})
	mux.HandleFunc("POST /api/v1/openvpn/export", func(w http.ResponseWriter, r *http.Request) {
		s.changeMu.Lock()
		defer s.changeMu.Unlock()
		if !ready(w) {
			return
		}
		var in struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON экспорта")
			return
		}
		if !openvpn.IDPattern.MatchString(in.ID) || in.Revision < 1 {
			fail(w, 422, "нужны ID и ревизия сохранённого профиля")
			return
		}
		snap, e := s.Store.ReadOpenVPN(r.Context())
		if e != nil {
			s.internal(w, e)
			return
		}
		if snap.Revision != in.Revision {
			fail(w, 412, "профили изменились; обновите данные")
			return
		}
		var found *openvpn.Profile
		for _, p := range snap.Config.Profiles {
			if p.ID == in.ID {
				found = &p
				break
			}
		}
		if found == nil {
			fail(w, 404, "профиль не найден")
			return
		}
		if e = s.Store.LogAudit(r.Context(), "openvpn.client.private_export.request:"+in.ID, snap.Revision); e != nil {
			s.internal(w, e)
			return
		}
		raw, e := s.PKI.ExportOpenVPN(*found)
		if e != nil {
			issue(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="gfw-openvpn.ovpn"`)
		_, _ = w.Write([]byte(raw))
	})
}
