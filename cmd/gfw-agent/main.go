package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/tuning"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/capture"
	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/netconfig"
	"github.com/rkislov/gfw/internal/openvpn"
	"github.com/rkislov/gfw/internal/policy"
	"github.com/rkislov/gfw/internal/services"
	"github.com/rkislov/gfw/internal/traffic"
	"github.com/rkislov/gfw/internal/vpncred"
	"github.com/rkislov/gfw/internal/wireguard"
	"github.com/rkislov/gfw/internal/xdpguard"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sysctl" {
		action := "plan"
		if len(os.Args) == 3 {
			action = os.Args[2]
		} else if len(os.Args) > 3 {
			log.Fatal("usage: gfw-sysctl [plan|apply|restore]")
		}
		p, err := tuning.Execute("plan", "")
		if err == nil && action != "plan" {
			p, err = tuning.Execute(action, p.Token)
		}
		if err != nil {
			log.Fatal(err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(p); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "vpn-auth" {
		if identity.RunOpenVPNHook(os.Args[2:]) != nil {
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	socket := flag.String("socket", "./data/agent.sock", "local Unix socket")
	group := flag.String("socket-group", "", "trusted controller group, e.g. gfw; members can administer the firewall")
	enabled := flag.Bool("enable-apply", false, "enable nftables mutation (Linux root only)")
	xdpEnabled := flag.Bool("enable-xdp", false, "enable WAN XDP filtering")
	captureEnabled := flag.Bool("enable-capture", false, "enable managed packet capture")
	captureDir := flag.String("capture-dir", "", "private capture storage; defaults to state-dir/captures")
	tcpdump := flag.String("tcpdump", "/usr/bin/tcpdump", "absolute trusted tcpdump executable")
	trafficEnabled := flag.Bool("enable-traffic", false, "collect conntrack and firewall NFLOG events")
	stateDir := flag.String("state-dir", "./data/agent-state", "private durable recovery directory")
	nft := flag.String("nft", "/usr/sbin/nft", "absolute nft executable path")
	idsEnabled := flag.Bool("enable-ids", false, "enable managed passive Suricata IDS")
	idsPath := flag.String("suricata", "/usr/bin/suricata", "absolute trusted Suricata binary")
	idsWork := flag.String("ids-runtime", "/run/gfw-ids", "private Suricata work directory")
	ipsecEnabled := flag.Bool("enable-ipsec", false, "enable managed IPsec/IKEv2")
	charon := flag.String("charon", "/usr/lib64/strongswan/ipsec/charon", "absolute trusted strongSwan daemon")
	swanctl := flag.String("swanctl", "/usr/sbin/swanctl", "absolute trusted swanctl")
	ipsecRuntime := flag.String("ipsec-runtime", "/run/gfw-agent/ipsec", "private IPsec runtime tmpfs directory")
	ovpnEnabled := flag.Bool("enable-openvpn", false, "enable managed OpenVPN server/client")
	ovpnPath := flag.String("openvpn", "/usr/sbin/openvpn", "trusted OpenVPN 2.6+ binary")
	ovpnRuntime := flag.String("openvpn-runtime", "/run/gfw-agent/openvpn", "private tmpfs directory for OpenVPN runtime secrets")
	wgEnabled := flag.Bool("enable-wireguard", false, "enable integrated kernel WireGuard management")
	servicesEnabled := flag.Bool("enable-services", false, "enable integrated DNS and DHCP modules")
	netEnabled := flag.Bool("enable-network", false, "enable static network management")
	netBackend := flag.String("network-backend", "etcnet", "static network backend: etcnet or netplan")
	ipPath := flag.String("ip", "/usr/bin/ip", "absolute iproute2 executable path")
	etcnetRoot := flag.String("etcnet-root", "/etc/net/ifaces", "etcnet interface configuration root")
	lan := flag.String("lan-interface", "", "required LAN interface for protected panel access")
	port := flag.Int("management-port", 0, "required actual TCP port of the management listener")
	flag.Parse()
	if (*netEnabled || *servicesEnabled || *wgEnabled || *ovpnEnabled || *ipsecEnabled || *idsEnabled || *trafficEnabled || *captureEnabled || *xdpEnabled) && !*enabled {
		return errors.New("agent runtime modules require enable-apply")
	}
	var manager *agent.Manager
	if *enabled {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return errors.New("apply requires Linux and root; local development remains read-only")
		}
		if !filepath.IsAbs(*nft) {
			return errors.New("nft path must be absolute")
		}
		info, err := os.Stat(*nft)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return errors.New("nft must be a root-owned executable not writable by group/others")
		}
		backendNFT := agent.NFT{Path: *nft}
		manager, err = agent.NewManager(*stateDir, backendNFT, policy.Safety{LANInterface: *lan, ManagementPort: *port})
		if err != nil {
			return err
		}
		defer manager.Close()
		manager.SetIPSBackend(backendNFT.ForIPS())
		manager.SetFlowBackend(backendNFT.ForFlow())
		if *netEnabled {
			if !filepath.IsAbs(*ipPath) {
				return errors.New("ip path must be absolute")
			}
			info, err := os.Stat(*ipPath)
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return errors.New("ip must be a trusted root-owned executable")
			}
			linux := netconfig.Linux{IP: *ipPath, Root: *etcnetRoot, LAN: *lan}
			switch *netBackend {
			case "etcnet":
				manager.SetNetworkBackend(linux)
			case "netplan":
				manager.SetNetworkBackend(netconfig.Netplan{Linux: linux})
			default:
				return errors.New("network-backend must be etcnet or netplan")
			}
		}
		if *servicesEnabled {
			root, e := filepath.Abs(filepath.Join(*stateDir, "services"))
			if e != nil {
				return e
			}
			backend := &services.Runtime{Root: root}
			manager.SetServicesBackend(backend)
			defer backend.Close()
		}
		if *wgEnabled {
			root, e := filepath.Abs(filepath.Join(*stateDir, "wireguard"))
			if e != nil {
				return e
			}
			vault, e := wireguard.OpenVault(root)
			if e != nil {
				return e
			}
			manager.SetWireGuardBackend(&wireguard.Linux{Vault: vault, LAN: *lan})
		}
		if *ovpnEnabled {
			root, e := filepath.Abs(filepath.Join(*stateDir, "openvpn"))
			if e != nil {
				return e
			}
			vault, e := openvpn.OpenVault(root)
			if e != nil {
				return e
			}
			backend, e := openvpn.NewLinux(vault, *lan, *ovpnPath, *ovpnRuntime)
			if e != nil {
				return e
			}
			manager.SetOpenVPNBackend(backend)
			defer manager.CloseOpenVPN(backend)
		}

		if *ipsecEnabled {
			vault, e := vpncred.OpenVault(filepath.Join(*stateDir, "ipsec"))
			if e != nil {
				return e
			}
			backend, e := ipsec.NewLinux(vault, *lan, *charon, *swanctl, *ipsecRuntime)
			if e != nil {
				return e
			}
			manager.SetIPsecBackend(backend)
			defer manager.CloseIPsec()
		}

		if *idsEnabled {
			backend, e := openIDS(*idsPath, *idsWork, filepath.Join(*stateDir, "ids"))
			if e != nil {
				slog.Error("Suricata IDS unavailable", "error", e)
			} else {
				manager.SetIDSBackend(backend)
				defer backend.Close()
			}
		}
		if *trafficEnabled {
			collector, e := traffic.Open(filepath.Join(*stateDir, "traffic"))
			if e != nil {
				slog.Error("traffic collection unavailable", "error", e)
			} else {
				manager.SetTraffic(collector)
				defer collector.Close()
			}
		}
		if *captureEnabled {
			if *captureDir == "" {
				*captureDir = filepath.Join(*stateDir, "captures")
			}
			captures, e := capture.Open(*captureDir, *tcpdump)
			if e != nil {
				slog.Error("packet capture unavailable", "error", e)
			} else {
				manager.SetCapture(captures)
				defer captures.Close()
			}
		}
		if *xdpEnabled {
			guard := xdpguard.New()
			manager.SetXDPBackend(guard)
			if guard != nil {
				defer guard.Deactivate()
			}
		}
		if err = manager.Recover(); err != nil {
			return err
		}
	}
	gid := -1
	if *group != "" {
		if os.Geteuid() != 0 {
			return errors.New("socket-group requires root")
		}
		g, err := user.LookupGroup(*group)
		if err != nil {
			return err
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return err
		}
	}
	dir := filepath.Dir(*socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return errors.New("socket directory must be owned by agent user and not writable by group/others")
	}
	if gid >= 0 {
		if err = os.Chown(dir, os.Geteuid(), gid); err != nil {
			return err
		}
		if err = os.Chmod(dir, 0750); err != nil {
			return err
		}
	} else if info.Mode().Perm()&0077 != 0 {
		return errors.New("socket directory must be private without socket-group")
	}
	// Only an apply agent holding the durable-state lock may clean its stale
	// socket, and never while another process still answers on that socket.
	if manager != nil {
		if info, e := os.Lstat(*socket); e == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return errors.New("socket path is not a socket")
			}
			c, e := net.DialTimeout("unix", *socket, time.Second)
			if e == nil {
				c.Close()
				return errors.New("another agent is listening on the socket")
			}
			if err = os.Remove(*socket); err != nil {
				return err
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	mode := os.FileMode(0600)
	if gid >= 0 {
		if err = os.Chown(*socket, os.Geteuid(), gid); err != nil {
			return err
		}
		mode = 0660
	}
	if err = os.Chmod(*socket, mode); err != nil {
		return err
	}
	srv := &http.Server{Handler: agent.Handler(manager), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	watchDone := make(chan struct{})
	watchStopped := make(chan struct{})
	defer func() { close(watchDone); <-watchStopped }()
	if manager != nil {
		go func() {
			defer close(watchStopped)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := manager.Tick(); err != nil {
						slog.Error("firewall recovery retry failed", "error", err)
					}
				case <-watchDone:
					return
				}
			}
		}()
	}
	if manager == nil {
		close(watchStopped)
	}

	errch := make(chan error, 1)
	go func() { errch <- srv.Serve(listener) }()
	slog.Info("agent started", "socket", *socket, "network_apply", manager != nil, "lan_interface", *lan, "management_port", *port)
	select {
	case err = <-errch:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdown)
	var rollbackErr error
	if manager != nil {
		rollbackErr = manager.Shutdown()
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, shutdownErr, rollbackErr)
}

func openIDS(path, work, state string) (ids.Backend, error) {
	account, err := user.Lookup("gfw-ids")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	return ids.NewRuntime(path, work, state, uint32(uid), uint32(gid))
}
