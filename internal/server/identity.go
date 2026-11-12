package server

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/rkislov/gfw/internal/identity"
)

type identityKey struct{}

func requestIdentity(r *http.Request) identity.User {
	u, _ := r.Context().Value(identityKey{}).(identity.User)
	return u
}

func (s *Server) EnableIdentity(dir string) error {
	db, err := identity.Open(dir)
	if err != nil {
		return err
	}
	s.identity = db
	return nil
}
func (s *Server) CloseIdentity() error {
	if s.identity == nil {
		return nil
	}
	return s.identity.Close()
}

func (s *Server) identityRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		users, err := s.identity.List(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		respond(w, 200, users)
	})
	api.HandleFunc("PUT /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		var in struct {
			identity.User
			Password  string `json:"password"`
			ResetTOTP bool   `json:"reset_totp"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "некорректная учётная запись")
			return
		}
		if err := s.Store.LogAuditActor(r.Context(), requestIdentity(r).Name, "identity.user.save:"+in.Name, 0); err != nil {
			s.internal(w, err)
			return
		}
		u, err := s.identity.Save(r.Context(), in.User, in.Password, in.ResetTOTP)
		if err != nil {
			identityError(w, err)
			return
		}
		respond(w, 200, u)
	})
	api.HandleFunc("GET /api/v1/users/ldap", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		config, err := s.identity.LDAP()
		if err != nil {
			s.internal(w, err)
			return
		}
		config.BindPassword = ""
		respond(w, 200, config)
	})
	api.HandleFunc("PUT /api/v1/users/ldap", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		var config identity.LDAPConfig
		if decode(w, r, &config) != nil {
			fail(w, 400, "некорректные настройки LDAP")
			return
		}
		if err := s.Store.LogAuditActor(r.Context(), requestIdentity(r).Name, "identity.ldap.save", 0); err != nil {
			s.internal(w, err)
			return
		}
		if err := s.identity.SaveLDAP(config); err != nil {
			identityError(w, err)
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	api.HandleFunc("GET /api/v1/users/radius", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		c, err := s.identity.Radius()
		if err != nil {
			s.internal(w, err)
			return
		}
		c.Secret = ""
		respond(w, 200, c)
	})
	api.HandleFunc("PUT /api/v1/users/radius", func(w http.ResponseWriter, r *http.Request) {
		if !s.identityReady(w) {
			return
		}
		var c identity.RadiusConfig
		if decode(w, r, &c) != nil {
			fail(w, 400, "некорректные настройки RADIUS")
			return
		}
		if err := s.Store.LogAuditActor(r.Context(), requestIdentity(r).Name, "identity.radius.save", 0); err != nil {
			s.internal(w, err)
			return
		}
		if err := s.identity.SaveRadius(c); err != nil {
			identityError(w, err)
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	api.HandleFunc("GET /api/v1/portal", s.portalState)
	api.HandleFunc("POST /api/v1/portal/export", s.portalExport)
	api.HandleFunc("POST /api/v1/portal/totp/begin", func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.portalUser(w, r)
		if !ok {
			return
		}
		var in struct {
			Password string `json:"password"`
		}
		if decode(w, r, &in) != nil || len(in.Password) > 1024 {
			fail(w, 400, "нужен текущий пароль")
			return
		}
		v, err := s.identity.BeginTOTP(r.Context(), u, in.Password)
		if err != nil {
			identityError(w, err)
			return
		}
		respond(w, 200, v)
	})
	api.HandleFunc("POST /api/v1/portal/totp/confirm", func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.portalUser(w, r)
		if !ok {
			return
		}
		var in struct {
			Code string `json:"code"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "нужен код TOTP")
			return
		}
		if err := s.Store.LogAuditActor(r.Context(), u.Name, "identity.totp.confirm", 0); err != nil {
			s.internal(w, err)
			return
		}
		u, err := s.identity.ConfirmTOTP(r.Context(), u, in.Code)
		if err != nil {
			identityError(w, err)
			return
		}
		// The enrollment changes the user's revision and invalidates all old sessions.
		s.logout(w, r)
	})
}

func (s *Server) identityReady(w http.ResponseWriter) bool {
	if s.identity != nil {
		return true
	}
	fail(w, 503, "хранилище пользователей недоступно")
	return false
}

func (s *Server) portalUser(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
	u := requestIdentity(r)
	if !s.identityReady(w) {
		return u, false
	}
	if u.Revision == 0 {
		fail(w, 403, "войдите под личной учётной записью")
		return u, false
	}
	return u, true
}

func identityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrDenied):
		fail(w, 401, "неверные данные входа")
	case errors.Is(err, identity.ErrBusy):
		fail(w, 429, "слишком много попыток, повторите позже")
	case errors.Is(err, identity.ErrConflict):
		fail(w, 409, err.Error())
	default:
		fail(w, 422, err.Error())
	}
}

func withIdentity(r *http.Request, u identity.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, u))
}

func (s *Server) VPNBroker(path, key string) (*http.Server, net.Listener, *net.UDPConn, error) {
	broker, listener, err := s.identity.ListenVPN(path, key)
	if err != nil {
		return nil, nil, nil, err
	}
	address, err := net.ResolveUDPAddr("udp4", identity.RadiusAddress)
	if err != nil {
		listener.Close()
		return nil, nil, nil, err
	}
	radius, err := net.ListenUDP("udp4", address)
	if err != nil {
		listener.Close()
		return nil, nil, nil, err
	}
	go broker.Serve(listener)
	go s.identity.ServeRadius(radius, key)
	return broker, listener, radius, nil
}
