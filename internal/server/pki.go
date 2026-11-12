package server

import (
	"database/sql"
	"errors"
	"github.com/rkislov/gfw/internal/pki"
	"net"
	"net/http"
)

func (s *Server) pkiRoutes(mux *http.ServeMux) {
	enabled := func(w http.ResponseWriter) bool {
		if s.PKI == nil {
			fail(w, 503, "менеджер сертификатов не подключён")
			return false
		}
		return true
	}
	result := func(w http.ResponseWriter, v any, e error) {
		if e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				fail(w, 404, "объект не найден")
			} else {
				fail(w, 422, e.Error())
			}
			return
		}
		respond(w, 200, v)
	}
	intent := func(w http.ResponseWriter, r *http.Request, action string) bool {
		if e := s.Store.LogAudit(r.Context(), action, 0); e != nil {
			s.internal(w, e)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/v1/pki", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		certs, e := s.PKI.List()
		if e != nil {
			s.internal(w, e)
			return
		}
		profiles, e := s.PKI.Profiles()
		if e != nil {
			s.internal(w, e)
			return
		}
		jobs, e := s.PKI.Jobs()
		if e != nil {
			s.internal(w, e)
			return
		}
		events, e := s.PKI.Audit()
		if e != nil {
			s.internal(w, e)
			return
		}
		respond(w, 200, map[string]any{"certificates": certs, "profiles": profiles, "jobs": jobs, "tls": s.PKI.TLSStatus(), "http01_enabled": s.PKI.ChallengesEnabled(), "audit": events})
	})
	mux.HandleFunc("POST /api/v1/pki/ca", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in pki.CARequest
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON CA")
			return
		}
		if !intent(w, r, "pki.ca.create.request") {
			return
		}
		v, e := s.PKI.CreateCA(in)
		result(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/pki/issue", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in pki.IssueRequest
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON выпуска")
			return
		}
		if !intent(w, r, "pki.certificate.issue.request") {
			return
		}
		v, e := s.PKI.Issue(in)
		result(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/pki/import", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in pki.ImportRequest
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный PEM JSON")
			return
		}
		if !intent(w, r, "pki.certificate.import.request") {
			return
		}
		v, e := s.PKI.Import(in)
		result(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/pki/certificates/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if !intent(w, r, "pki.certificate.revoke.request:"+r.PathValue("id")) {
			return
		}
		v, e := s.PKI.Revoke(r.PathValue("id"))
		if e != nil {
			result(w, v, e)
			return
		}
		status := "unmanaged"
		syncError := ""
		if s.AgentSocket != "" {
			status = "synced"
			if err := errors.Join(s.SyncOpenVPN(r.Context()), s.SyncIPsec(r.Context())); err != nil {
				status = "pending"
				syncError = err.Error()
			}
		}
		result(w, struct {
			pki.Certificate
			CRLSyncStatus string `json:"crl_sync_status"`
			CRLSyncError  string `json:"crl_sync_error,omitempty"`
		}{v, status, syncError}, nil)
	})
	for _, kind := range []string{"pem", "crl"} {
		mux.HandleFunc("GET /api/v1/pki/certificates/{id}/"+kind, func(w http.ResponseWriter, r *http.Request) {
			if !enabled(w) {
				return
			}
			var raw []byte
			var e error
			if kind == "pem" {
				raw, e = s.PKI.PublicPEM(r.PathValue("id"))
			} else {
				raw, e = s.PKI.CRL(r.PathValue("id"))
			}
			if e != nil {
				result(w, nil, e)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="gfw-certificate.`+kind+`"`)
			_, _ = w.Write(raw)
		})
	}
	mux.HandleFunc("POST /api/v1/pki/acme/profiles", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in pki.ProfileRequest
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON ACME")
			return
		}
		if !intent(w, r, "pki.acme.profile.create.request") {
			return
		}
		v, e := s.PKI.CreateProfile(in)
		result(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/pki/acme/profiles/{id}/issue", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if !intent(w, r, "pki.acme.issue.request:"+r.PathValue("id")) {
			return
		}
		v, e := s.PKI.Queue(r.PathValue("id"))
		result(w, v, e)
	})
	mux.HandleFunc("PUT /api/v1/pki/acme/profiles/{id}/auto-renew", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON продления")
			return
		}
		if !intent(w, r, "pki.acme.auto_renew.request:"+r.PathValue("id")) {
			return
		}
		result(w, map[string]bool{"ok": true}, s.PKI.SetAutoRenew(r.PathValue("id"), in.Enabled))
	})
	host := func(r *http.Request) string {
		if h, _, e := net.SplitHostPort(r.Host); e == nil {
			return h
		}
		return r.Host
	}
	mux.HandleFunc("POST /api/v1/pki/tls/apply", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if r.TLS == nil {
			fail(w, 422, "откройте панель через HTTPS перед заменой сертификата")
			return
		}
		var in struct {
			ID             string `json:"id"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON TLS")
			return
		}
		if !intent(w, r, "pki.tls.apply.request:"+in.ID) {
			return
		}
		v, e := s.PKI.SwitchTLS(r.Context(), in.ID, host(r), in.TimeoutSeconds)
		result(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/pki/tls/confirm", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if r.TLS == nil {
			fail(w, 422, "требуется HTTPS")
			return
		}
		var in struct {
			ID string `json:"id"`
		}
		if decode(w, r, &in) != nil {
			fail(w, 400, "неверный JSON TLS")
			return
		}
		if !intent(w, r, "pki.tls.confirm.request:"+in.ID) {
			return
		}
		result(w, map[string]bool{"ok": true}, s.PKI.ConfirmTLS(in.ID, host(r)))
	})
	mux.HandleFunc("POST /api/v1/pki/tls/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		if !intent(w, r, "pki.tls.rollback.request") {
			return
		}
		result(w, map[string]bool{"ok": true}, s.PKI.RollbackTLS())
	})
}
