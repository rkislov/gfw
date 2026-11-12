package fess

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rkislov/gfw/internal/engines/fess/engine"
	"github.com/rkislov/gfw/internal/engines/fess/policy"
	"github.com/rkislov/gfw/internal/engines/fess/routing"
)

type Certificate func(id, hostname string) (*tls.Certificate, error)

type Event struct {
	At       time.Time `json:"at"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Client   string    `json:"client"`
	Rule     string    `json:"rule"`
	Decision string    `json:"decision"`
}

type route struct {
	site  Site
	rules policy.Snapshot
	body  bool
	proxy *httputil.ReverseProxy
}

type Publication struct {
	Config
	routes    map[string][]route
	certs     map[string]string
	transport *http.Transport
}

type endpoint struct {
	net.Listener
	runtime *Runtime
	address string
	server  *http.Server
}

type Runtime struct {
	mu        sync.Mutex
	cert      Certificate
	reserved  []string
	current   atomic.Pointer[Publication]
	endpoints map[string]*endpoint
	log       func(Event)
	slots     chan struct{}
}

func New(cert Certificate, log func(Event), reserved ...string) *Runtime {
	return &Runtime{cert: cert, log: log, reserved: reserved, endpoints: map[string]*endpoint{}, slots: make(chan struct{}, 32)}
}

func (r *Runtime) Prepare(c Config) (*Publication, error) {
	if err := Validate(c, r.reserved...); err != nil {
		return nil, err
	}
	p := &Publication{Config: c, routes: map[string][]route{}, certs: map[string]string{}}
	if !c.Enabled {
		return p, nil
	}
	p.transport = &http.Transport{DialContext: r.dial, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 64, MaxConnsPerHost: 32}
	for _, s := range c.Sites {
		if c.TLS && p.certs[s.Host] == "" {
			if _, err := r.cert(s.Certificate, s.Host); err != nil {
				return nil, fmt.Errorf("TLS %s: %w", s.Host, err)
			}
			p.certs[s.Host] = s.Certificate
		}
		upstream, _ := url.Parse(s.Upstream)
		rules, body, _ := compileRules(s)
		proxy := &httputil.ReverseProxy{
			Transport: p.transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.SetURL(upstream)
				request.SetXForwarded()
				request.Out.Header.Del("X-GFW-CSRF")
				request.Out.Header.Del("Cookie")
				for _, cookie := range request.In.Cookies() {
					if !strings.EqualFold(cookie.Name, "gfw_session") {
						request.Out.AddCookie(cookie)
					}
				}
			},
			ModifyResponse: func(response *http.Response) error {
				cookies := response.Header.Values("Set-Cookie")
				response.Header.Del("Set-Cookie")
				for _, cookie := range cookies {
					name, _, _ := strings.Cut(cookie, "=")
					if !strings.EqualFold(strings.TrimSpace(name), "gfw_session") {
						response.Header.Add("Set-Cookie", cookie)
					}
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "Upstream unavailable", http.StatusBadGateway)
			},
		}
		rt := route{site: s, body: body, proxy: proxy, rules: policy.Snapshot{Policies: []policy.CompiledPolicy{{ID: "site", Mode: s.Mode, Rules: rules}}}}
		p.routes[s.Host] = append(p.routes[s.Host], rt)
	}
	for _, routes := range p.routes {
		slices.SortFunc(routes, func(a, b route) int { return len(b.site.Path) - len(a.site.Path) })
	}
	return p, nil
}

func (r *Runtime) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	blockedPort := false
	for _, a := range r.reserved {
		blockedPort = blockedPort || port(a) == p
	}
	r.mu.Lock()
	for a := range r.endpoints {
		blockedPort = blockedPort || port(a) == p
	}
	r.mu.Unlock()
	if !blockedPort {
		return dialer.DialContext(ctx, network, address)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := map[netip.Addr]bool{}
	for _, a := range ifaces {
		if prefix, e := netip.ParsePrefix(a.String()); e == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() || local[ip] {
			continue
		}
		conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), p))
		if e == nil {
			return conn, nil
		}
	}
	return nil, errors.New("upstream port unavailable or reserved on this host")
}

func (r *Runtime) CheckBind(p *Publication) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !p.Enabled || r.endpoints[p.Listen] != nil {
		return nil
	}
	listener, err := net.Listen("tcp", p.Listen)
	if err != nil {
		return err
	}
	return listener.Close()
}

func (r *Runtime) Set(p *Publication) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p != nil && p.Enabled && r.endpoints[p.Listen] == nil {
		listener, err := net.Listen("tcp", p.Listen)
		if err != nil {
			return err
		}
		e := &endpoint{Listener: listener, address: p.Listen, runtime: r}
		e.server = &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
		r.endpoints[p.Listen] = e
		go func() { _ = e.server.Serve(e) }()
	}
	if previous := r.current.Swap(p); previous != nil && previous.transport != nil {
		previous.transport.CloseIdleConnections()
	}
	return nil
}

func (r *Runtime) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.current.Load()
	for address, e := range r.endpoints {
		if p == nil || !p.Enabled || address != p.Listen {
			_ = e.server.Close()
			_ = e.Listener.Close()
			delete(r.endpoints, address)
		}
	}
}

func (e *endpoint) Accept() (net.Conn, error) {
	conn, err := e.Listener.Accept()
	if err != nil {
		return nil, err
	}
	p := e.runtime.current.Load()
	if p == nil || !p.Enabled || p.Listen != e.address || !p.TLS {
		return conn, nil
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := strings.ToLower(hello.ServerName)
		id := p.certs[host]
		if id == "" {
			return nil, errors.New("unknown TLS host")
		}
		return e.runtime.cert(id, host)
	}}
	return tls.Server(conn, config), nil
}

func (e *endpoint) serve(w http.ResponseWriter, req *http.Request) {
	r := e.runtime
	p := r.current.Load()
	if p == nil || !p.Enabled || p.Listen != e.address {
		http.Error(w, "Publication unavailable", 503)
		return
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		http.Error(w, "Gateway busy", 503)
		return
	}
	host := strings.ToLower(req.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if p.TLS != (req.TLS != nil) || (req.TLS != nil && !strings.EqualFold(req.TLS.ServerName, host)) {
		http.Error(w, "Misdirected request", 421)
		return
	}
	if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" || strings.Contains(req.URL.Path, "\\") {
		http.Error(w, "Unsupported request", 400)
		return
	}
	for _, part := range strings.Split(req.URL.Path, "/") {
		if part == "." || part == ".." {
			http.Error(w, "Invalid path", 400)
			return
		}
	}
	for _, route := range p.routes[host] {
		if routing.PathMatchesPrefix(req.URL.Path, route.site.Path) {
			e.proxy(w, req, host, route)
			return
		}
	}
	http.NotFound(w, req)
}

func (e *endpoint) proxy(w http.ResponseWriter, req *http.Request, host string, route route) {
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	req = req.Clone(ctx)
	req.URL.Path = routing.StripPathPrefix(req.URL.Path, route.site.Path)
	req.URL.RawPath = ""
	var body []byte
	if route.body && req.Body != nil && req.Body != http.NoBody {
		if encoding := req.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
			http.Error(w, "Unsupported content encoding", 415)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			http.Error(w, "Request body unavailable or exceeds 1 MiB", 413)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	client, _, _ := net.SplitHostPort(req.RemoteAddr)
	decision := engine.NewEvaluator().EvaluateBody(req, route.rules, "site", client, body)
	if decision.RuleID != "" {
		action := "log"
		if decision.PolicyMode == "block" && decision.Action == "block" {
			action = "block"
		}
		e.runtime.record(Event{time.Now().UTC(), host, req.URL.Path, client, decision.RuleID, action})
		if action == "block" {
			http.Error(w, "Request blocked", 403)
			return
		}
	}
	route.proxy.ServeHTTP(w, req)
}

func (r *Runtime) record(event Event) {
	if len(event.Path) > 256 {
		event.Path = event.Path[:256]
	}
	r.log(event)
}
