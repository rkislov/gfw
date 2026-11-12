package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/network"
	"github.com/rkislov/gfw/internal/pki"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/store"
	"github.com/rkislov/gfw/internal/web"
)

type session struct {
	User    identity.User
	CSRF    string
	Expires time.Time
}
type Server struct {
	identity      *identity.Store
	traffic       *trafficManager
	fess          *fessManager
	feed          *feedManager
	ipsecCRLSync  CRLSyncStatus
	ipsecCRLSent  map[string]string
	crlMu         sync.Mutex
	crlSync       CRLSyncStatus
	crlSent       map[string]string
	PKI           *pki.Manager
	Store         *store.Store
	Token         string
	AgentSocket   string
	mu            sync.Mutex
	changeMu      sync.Mutex
	fileIOCMu     sync.Mutex
	sessions      map[string]session
	loginWindow   time.Time
	loginAttempts int
}

func New(s *store.Store, token, agent string) *Server {
	return &Server{Store: s, Token: token, AgentSocket: agent, sessions: map[string]session{}}
}
func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("ожидался один JSON-объект")
	}
	return nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(web.Assets, "assets")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(assets)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := web.Assets.ReadFile("assets/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	api := http.NewServeMux()
	s.identityRoutes(api)
	s.sysctlRoutes(api)
	s.pkiRoutes(api)
	s.feedRoutes(api)
	s.idsRoutes(api)
	s.fessRoutes(api)
	s.trafficRoutes(api)
	s.captureRoutes(api)
	s.xdpRoutes(api)
	s.openVPNRoutes(api)
	api.HandleFunc("GET /api/v1/auth/me", s.me)
	api.HandleFunc("POST /api/v1/auth/logout", s.logout)
	api.HandleFunc("GET /api/v1/status", s.status)
	api.HandleFunc("GET /api/v1/interfaces", s.interfaces)
	api.HandleFunc("GET /api/v1/metrics", s.metrics)

	api.HandleFunc("GET /api/v1/ipsec/config", s.ipsecConfig)
	api.HandleFunc("PUT /api/v1/ipsec/config", s.saveIPsec)
	api.HandleFunc("GET /api/v1/ipsec/state", s.ipsecState)
	api.HandleFunc("POST /api/v1/ipsec/plan", s.ipsecPlan)
	api.HandleFunc("POST /api/v1/ipsec/apply", s.ipsecApply)
	api.HandleFunc("POST /api/v1/ipsec/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/ipsec/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/ipsec/logs", s.ipsecLogs)

	api.HandleFunc("GET /api/v1/openvpn/runtime/config", s.openvpnRuntimeConfig)
	api.HandleFunc("PUT /api/v1/openvpn/runtime/config", s.saveOpenVPNRuntime)
	api.HandleFunc("GET /api/v1/openvpn/runtime/state", s.openvpnRuntimeState)
	api.HandleFunc("POST /api/v1/openvpn/runtime/plan", s.openvpnRuntimePlan)
	api.HandleFunc("POST /api/v1/openvpn/runtime/apply", s.openvpnRuntimeApply)
	api.HandleFunc("POST /api/v1/openvpn/runtime/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/openvpn/runtime/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/openvpn/runtime/logs/{id}", s.openvpnRuntimeLogs)
	api.HandleFunc("POST /api/v1/openvpn/runtime/crl-sync", func(w http.ResponseWriter, r *http.Request) {
		if e := s.SyncOpenVPN(r.Context()); e != nil {
			s.agentError(w, e)
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})

	api.HandleFunc("GET /api/v1/wireguard/config", s.wireguardConfig)
	api.HandleFunc("PUT /api/v1/wireguard/config", s.saveWireGuard)
	api.HandleFunc("GET /api/v1/wireguard/state", s.wireguardState)
	api.HandleFunc("POST /api/v1/wireguard/plan", s.wireguardPlan)
	api.HandleFunc("POST /api/v1/wireguard/apply", s.wireguardApply)
	api.HandleFunc("POST /api/v1/wireguard/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/wireguard/changes/{id}/rollback", s.rollback)
	api.HandleFunc("POST /api/v1/wireguard/keys", s.wireGuardKey)
	api.HandleFunc("POST /api/v1/wireguard/export", s.wireGuardExport)
	api.HandleFunc("GET /api/v1/services/config", s.servicesConfig)
	api.HandleFunc("PUT /api/v1/services/config", s.saveServices)
	api.HandleFunc("GET /api/v1/services/state", s.servicesState)
	api.HandleFunc("POST /api/v1/services/plan", s.servicesPlan)
	api.HandleFunc("POST /api/v1/services/apply", s.servicesApply)
	api.HandleFunc("POST /api/v1/services/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/services/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/services/leases", s.serviceLeases)
	api.HandleFunc("GET /api/v1/services/dns-logs", s.serviceDNSLogs)
	api.HandleFunc("GET /api/v1/network/config", s.networkConfig)
	api.HandleFunc("PUT /api/v1/network/config", s.saveNetwork)
	api.HandleFunc("GET /api/v1/network/state", s.networkState)
	api.HandleFunc("POST /api/v1/network/plan", s.networkPlan)
	api.HandleFunc("POST /api/v1/network/apply", s.networkApply)
	api.HandleFunc("POST /api/v1/network/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/network/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/config", s.config)
	api.HandleFunc("PUT /api/v1/config", s.save)
	api.HandleFunc("POST /api/v1/changes/plan", s.plan)
	api.HandleFunc("GET /api/v1/changes/state", s.changeState)
	api.HandleFunc("GET /api/v1/firewall/flow", s.flowState)
	api.HandleFunc("POST /api/v1/changes/apply", s.apply)
	api.HandleFunc("POST /api/v1/changes/{id}/confirm", s.confirm)
	api.HandleFunc("POST /api/v1/changes/{id}/rollback", s.rollback)
	api.HandleFunc("GET /api/v1/audit", s.audit)
	mux.Handle("/api/v1/", s.authorize(api))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				if e != nil || u.Host != r.Host || u.Scheme != scheme {
					fail(w, 403, "запрос с другого origin запрещён")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if decode(w, r, &in) != nil {
		fail(w, 400, "некорректный JSON")
		return
	}
	now := time.Now()
	u := identity.User{Name: "admin", Role: "admin"}
	if in.Username != "" {
		if !s.identityReady(w) {
			return
		}
		var err error
		u, err = s.identity.Authenticate(r.Context(), in.Username, in.Password, in.Code, identity.Method{}, "", true)
		if err != nil {
			identityError(w, err)
			return
		}
	} else {
		s.mu.Lock()
		if now.Sub(s.loginWindow) > time.Minute {
			s.loginWindow = now
			s.loginAttempts = 0
		}
		s.loginAttempts++
		limited := s.loginAttempts > 10
		s.mu.Unlock()
		if limited {
			w.Header().Set("Retry-After", "60")
			fail(w, 429, "слишком много попыток входа")
			return
		}
		if subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.Token)) != 1 {
			fail(w, 401, "неверный ключ администратора")
			return
		}
	}
	id := random()
	ss := session{User: u, CSRF: random(), Expires: now.Add(8 * time.Hour)}
	s.mu.Lock()
	for k, v := range s.sessions {
		if now.After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= 64 {
		s.mu.Unlock()
		fail(w, 429, "слишком много активных сессий")
		return
	}
	s.sessions[id] = ss
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "gfw_session", Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	respond(w, 200, map[string]string{"user": u.Name, "role": u.Role, "csrf": ss.CSRF})
}
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(s.Token)) == 1 {
			next.ServeHTTP(w, withIdentity(r, identity.User{Name: "admin", Role: "admin"}))
			return
		}
		cookie, err := r.Cookie("gfw_session")
		if err != nil {
			fail(w, 401, "требуется вход")
			return
		}
		s.mu.Lock()
		ss, ok := s.sessions[cookie.Value]
		if ok && time.Now().After(ss.Expires) {
			delete(s.sessions, cookie.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			fail(w, 401, "сессия завершена")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-GFW-CSRF")), []byte(ss.CSRF)) != 1 {
			fail(w, 403, "неверный CSRF-токен")
			return
		}
		u := ss.User
		if u.Revision != 0 {
			if s.identity == nil {
				fail(w, 401, "сессия завершена")
				return
			}
			current, err := s.identity.User(r.Context(), u.Name)
			if err != nil || current.Disabled || current.Revision != u.Revision {
				s.mu.Lock()
				delete(s.sessions, cookie.Value)
				s.mu.Unlock()
				fail(w, 401, "сессия завершена")
				return
			}
			u = current
		}
		if u.Role != "admin" && r.URL.Path != "/api/v1/auth/me" && r.URL.Path != "/api/v1/auth/logout" &&
			r.URL.Path != "/api/v1/portal" && !strings.HasPrefix(r.URL.Path, "/api/v1/portal/") {
			fail(w, 403, "требуется роль администратора")
			return
		}
		next.ServeHTTP(w, withIdentity(r, u))
	})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	csrf := ""
	if c, e := r.Cookie("gfw_session"); e == nil {
		s.mu.Lock()
		csrf = s.sessions[c.Value].CSRF
		s.mu.Unlock()
	}
	u := requestIdentity(r)
	respond(w, 200, map[string]any{"user": u.Name, "role": u.Role, "personal": u.Revision != 0, "csrf": csrf})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("gfw_session"); e == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "gfw_session", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}

var version = "0.22.3-dev"

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.Read(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	source := "controller"
	if s.AgentSocket != "" {
		source = "agent"
	}
	state, agentErr := s.agentState(r)
	mode := "preview"
	firewallStatus := "preview"
	if state.Enabled {
		mode = "managed"
		firewallStatus = "active"
	}
	if agentErr != nil {
		mode = "agent_unavailable"
	}
	feedStatus := "unavailable"
	if s.feed != nil {
		feedStatus = "integrated"
	}
	captureStatus := "unavailable"
	var caps map[string]bool
	if s.AgentSocket != "" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		_ = agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/capabilities", nil, &caps)
		cancel()
	}
	xdpStatus := "unavailable"
	if caps["xdp"] {
		xdpStatus = "active"
	}
	if caps["capture"] {
		captureStatus = "active"
	}
	respond(w, 200, map[string]any{"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "revision": snap.Revision, "mode": mode, "inventory_source": source, "capabilities": map[string]bool{"interface_inventory": true, "policy_drafts": true, "nftables_preview": true, "network_apply": state.Enabled && agentErr == nil, "capture": caps["capture"], "xdp": caps["xdp"], "traffic_database": s.traffic != nil}, "modules": []map[string]string{
		{"id": "firewall", "name": "Firewall / nftables", "status": firewallStatus}, {"id": "gdns", "name": "Go DNS", "status": "integrated"}, {"id": "gdhcp", "name": "Go DHCP", "status": "integrated"}, {"id": "wireguard", "name": "WireGuard VPN", "status": "integrated"}, {"id": "openvpn", "name": "OpenVPN сервер / клиент", "status": "integrated"}, {"id": "ipsec", "name": "IPsec / IKEv2", "status": "integrated"}, {"id": "pki", "name": "CA / ACME", "status": "integrated"}, {"id": "fess", "name": "FESS reverse proxy / WAF", "status": "integrated"}, {"id": "feed", "name": "feed.kislovs.ru", "status": feedStatus}, {"id": "suricata", "name": "Suricata IDS/IPS", "status": "integrated"}, {"id": "capture", "name": "Захват пакетов", "status": captureStatus}, {"id": "xdp", "name": "Ранняя фильтрация XDP", "status": xdpStatus}, {"id": "traffic", "name": "ClickHouse traffic logs", "status": "integrated"},
	}})
}
func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	var links []network.Interface
	var err error
	if s.AgentSocket == "" {
		links, err = network.Inventory()
	} else {
		links, err = network.FromAgent(r.Context(), s.AgentSocket)
	}
	if err != nil {
		slog.Error("interface inventory failed", "error", err)
		fail(w, 503, "инвентаризация недоступна; проверьте агент")
		return
	}
	respond(w, 200, links)
}
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.Read(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) save(w http.ResponseWriter, r *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	header := r.Header.Get("If-Match")
	if header == "" {
		fail(w, 428, "нужен If-Match текущей ревизии")
		return
	}
	v, err := strconv.Unquote(header)
	if err != nil {
		fail(w, 400, "некорректный If-Match")
		return
	}
	revision, err := strconv.ParseInt(v, 10, 64)
	if err != nil || revision < 1 {
		fail(w, 400, "некорректная ревизия")
		return
	}
	var c policy.Config
	if err = decode(w, r, &c); err != nil {
		fail(w, 400, "некорректный JSON конфигурации")
		return
	}
	draft, err := s.Store.Read(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if draft.Revision != revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	c.SecurityFeed = draft.Config.SecurityFeed
	if c.SecurityFeed != nil && !fitsFeedDraft(c) {
		fail(w, 422, "Черновик firewall со списком превышает размер запроса агента")
		return
	}
	if err = policy.Validate(c); err != nil {
		fail(w, 422, err.Error())
		return
	}
	snap, err := s.Store.Save(r.Context(), revision, c)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 412, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(snap.Revision, 10)))
	respond(w, 200, snap)
}
func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	var c policy.Config
	if err := decode(w, r, &c); err != nil {
		fail(w, 400, "некорректный JSON конфигурации")
		return
	}
	text, err := policy.Compile(c)
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	state, err := s.agentState(r)
	if err != nil {
		s.agentError(w, err)
		return
	}
	if state.Enabled {
		var plan agent.Plan
		err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/firewall/plan", c, &plan)
		if err != nil {
			s.agentError(w, err)
			return
		}
		respond(w, 200, plan)
		return
	}
	respond(w, 200, map[string]any{"nftables": text, "can_apply": false, "kernel_validated": false, "warnings": []string{"Локальный предпросмотр: проверка nft на Linux не выполнялась.", "Применение требует Linux-агента с включённым управлением и обязательным anti-lockout для LAN."}})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	events, err := s.Store.Audit(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	respond(w, 200, events)
}
func (s *Server) internal(w http.ResponseWriter, err error) {
	slog.Error("request failed", "error", err)
	fail(w, 500, "внутренняя ошибка; проверьте журнал службы")
}
