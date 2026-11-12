package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	dhcpcore "github.com/rkislov/gfw/internal/engines/gdhcp/core"
	"github.com/rkislov/gfw/internal/engines/gdhcp/model"
	dhcpserver "github.com/rkislov/gfw/internal/engines/gdhcp/server"
	dhcpstorage "github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	dnsengine "github.com/rkislov/gfw/internal/engines/gdns/core"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

type Backend interface {
	Prepare(Config) (Plan, error)
	Activate(Config) error
	Verify(Config) error
	Close() error
	Status() Status
}
type Status struct {
	DNSRunning  bool   `json:"dns_running"`
	DHCPRunning int    `json:"dhcp_running"`
	Error       string `json:"error,omitempty"`
}
type Lease struct {
	Pool      string    `json:"pool"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Runtime struct {
	opMu       sync.Mutex
	mu         sync.Mutex
	Root       string
	config     Config
	active     bool
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	dnsServers []*dns.Server
	sockets    []io.Closer
	stores     []dhcpstorage.Store
	poolIDs    []string
	engine     *dnsengine.Engine
	failure    error
}

func (r *Runtime) Prepare(c Config) (Plan, error) {
	p := Preview(c)
	if e := Validate(c); e != nil {
		return p, e
	}
	for name, ips := range Interfaces(c) {
		link, e := net.InterfaceByName(name)
		if e != nil {
			return p, fmt.Errorf("интерфейс %s не найден", name)
		}
		if link.Flags&net.FlagUp == 0 {
			return p, fmt.Errorf("интерфейс %s выключен", name)
		}
		addresses, e := link.Addrs()
		if e != nil {
			return p, e
		}
		for _, s := range ips {
			a, _ := netip.ParseAddr(s)
			found := false
			for _, raw := range addresses {
				n, e := netip.ParsePrefix(raw.String())
				if e == nil && n.Addr() == a {
					found = true
				}
			}
			if !found {
				return p, fmt.Errorf("адрес %s не назначен интерфейсу %s", s, name)
			}
		}
	}
	p.CanApply = true
	return p, nil
}
func (r *Runtime) serve(ctx context.Context, name string, fn func() error) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if e := fn(); ctx.Err() == nil {
			if e == nil {
				e = errors.New("listener stopped")
			}
			r.mu.Lock()
			r.failure = fmt.Errorf("%s: %w", name, e)
			r.mu.Unlock()
		}
	}()
}

// stopLocked joins all users of lease stores before closing those stores.
func (r *Runtime) stopLocked() error {
	if r.cancel != nil {
		r.cancel()
	}
	for _, s := range r.sockets {
		_ = s.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range r.dnsServers {
		_ = s.ShutdownContext(ctx)
	}
	// Error reporters use mu. Release it while joining after cancellation.
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
	var err error
	for _, s := range r.stores {
		err = errors.Join(err, s.Close())
	}
	r.stores = nil
	r.poolIDs = nil
	r.sockets = nil
	r.dnsServers = nil
	r.cancel = nil
	r.engine = nil
	r.active = false
	r.failure = nil
	return err
}
func (r *Runtime) Activate(c Config) error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	if _, e := r.Prepare(c); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.stopLocked(); e != nil {
		return e
	}
	if !filepath.IsAbs(r.Root) {
		return errors.New("service data root must be absolute")
	}
	if e := os.MkdirAll(r.Root, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(r.Root)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("service data root must be a private directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	fail := func(e error) error { _ = r.stopLocked(); return e }
	if c.DNS.Enabled {
		engine, e := dnsengine.New(DNSConfig(c.DNS))
		if e != nil {
			return fail(e)
		}
		r.engine = engine
		lc := net.ListenConfig{Control: bindInterface(c.DNS.Interface)}
		address := net.JoinHostPort(c.DNS.Address, fmt.Sprint(c.DNS.Port))
		udp, e := lc.ListenPacket(ctx, "udp", address)
		if e != nil {
			return fail(e)
		}
		r.sockets = append(r.sockets, udp)
		tcp, e := lc.Listen(ctx, "tcp", address)
		if e != nil {
			return fail(e)
		}
		r.sockets = append(r.sockets, tcp)
		for _, s := range []*dns.Server{{PacketConn: udp, Net: "udp", Handler: engine, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}, {Listener: tcp, Net: "tcp", Handler: engine, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: func() time.Duration { return 5 * time.Second }, MaxTCPQueries: 100}} {
			ready := make(chan struct{})
			s.NotifyStartedFunc = func() { close(ready) }
			r.dnsServers = append(r.dnsServers, s)
			r.serve(ctx, "DNS", s.ActivateAndServe)
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				return fail(errors.New("DNS listener did not become ready"))
			}
		}
	}
	if c.DHCP.Enabled {
		for _, p := range c.DHCP.Pools {
			sum := sha256.Sum256([]byte(p.ID))
			path := filepath.Join(r.Root, "leases-"+hex.EncodeToString(sum[:12])+".db")
			file, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if e != nil {
				return fail(e)
			}
			_ = file.Close()
			if e = os.Chmod(path, 0600); e != nil {
				return fail(e)
			}
			store, e := dhcpstorage.Open(ctx, "sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)")
			if e != nil {
				return fail(e)
			}
			r.stores = append(r.stores, store)
			r.poolIDs = append(r.poolIDs, p.ID)
			// Lease durability survives service rollback and a machine restart.
			log := slog.Default().With("module", "dhcp", "pool", p.ID)
			service, e := dhcpcore.New(ctx, dhcpcore.Options{Store: store, Config: DHCPConfig(c.DHCP, p, path), Logger: log})
			if e != nil {
				return fail(e)
			}
			listener, e := dhcpserver.ListenInterface(":"+fmt.Sprint(c.DHCP.Port), p.Interface)
			if e != nil {
				return fail(e)
			}
			r.sockets = append(r.sockets, listener)
			r.serve(ctx, "DHCP "+p.Name, func() error { return listener.Serve(ctx, service, log) })
			r.wg.Add(1)
			go func() { defer r.wg.Done(); service.RunJanitor(ctx, 30*time.Second) }()
		}
	}
	r.config = c
	r.active = true
	return nil
}
func (r *Runtime) Verify(c Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		return r.failure
	}
	if !r.active || !reflect.DeepEqual(r.config, c) {
		return errors.New("service runtime does not match configuration")
	}
	return nil
}
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{DNSRunning: r.engine != nil, DHCPRunning: len(r.stores)}
	if r.failure != nil {
		s.Error = r.failure.Error()
	}
	return s
}
func (r *Runtime) Close() error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopLocked()
}
func (r *Runtime) Leases(ctx context.Context) ([]Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Lease{}
	for i, s := range r.stores {
		ls, _, e := s.ListLeases(ctx, model.LeaseFilter{Limit: 200})
		if e != nil {
			return nil, e
		}
		for _, l := range ls {
			out = append(out, Lease{Pool: r.poolIDs[i], IP: l.IP, MAC: l.MAC, Hostname: l.Hostname, State: string(l.State), ExpiresAt: l.ExpiresAt})
		}
	}
	return out, nil
}
func (r *Runtime) DNSLogs() any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.engine == nil {
		return []any{}
	}
	return r.engine.RecentLogs(100)
}
func Equal(a, b Config) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
