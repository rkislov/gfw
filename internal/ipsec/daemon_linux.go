//go:build linux

package ipsec

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/vpncred"
	"golang.org/x/sys/unix"
)

type daemon struct {
	lock    *os.File
	charon  string
	swanctl string
	dir     string
	cmd     *exec.Cmd
	done    chan struct{}
	log     logTail
}

type logTail struct {
	mu   sync.Mutex
	data []byte
}

func (l *logTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	const size = 128 << 10
	n := len(p)
	if n >= size {
		l.data = append(l.data[:0], p[n-size:]...)
		return n, nil
	}
	if overflow := len(l.data) + n - size; overflow > 0 {
		copy(l.data, l.data[overflow:])
		l.data = l.data[:len(l.data)-overflow]
	}
	l.data = append(l.data, p...)
	return n, nil
}
func (l *logTail) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(l.data)), "\n")
	if len(lines) > 200 {
		return lines[len(lines)-200:]
	}
	return lines
}

type commandOutput struct{ bytes.Buffer }

func (b *commandOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 256<<10 {
		return 0, errors.New("swanctl output exceeds limit")
	}
	return b.Buffer.Write(p)
}

var _ io.Writer = (*commandOutput)(nil)

func trusted(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("strongSwan executable path must be absolute")
	}
	i, e := os.Stat(path)
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Mode().Perm()&0111 == 0 {
		return errors.New("unsafe strongSwan executable")
	}
	return nil
}
func newDaemon(charon, swanctl, dir string) (*daemon, error) {
	if e := trusted(charon); e != nil {
		return nil, e
	}
	if e := trusted(swanctl); e != nil {
		return nil, e
	}
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, " \r\n\t{}#=\"\\") || len(dir) > 75 {
		return nil, errors.New("invalid IPsec runtime path")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("IPsec runtime must be a private root directory")
	}
	var fs unix.Statfs_t
	if e = unix.Statfs(dir, &fs); e != nil {
		return nil, e
	}
	if fs.Type != unix.TMPFS_MAGIC {
		return nil, errors.New("IPsec runtime requires tmpfs")
	}
	lock, e := os.OpenFile(filepath.Join(dir, "runtime.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("IPsec runtime already belongs to another agent")
	}
	if e = os.RemoveAll(filepath.Join(dir, "credentials")); e != nil {
		lock.Close()
		return nil, e
	}
	return &daemon{charon: charon, swanctl: swanctl, dir: dir, lock: lock}, nil
}
func (d *daemon) command(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args = append(args, "--uri", "unix://"+filepath.Join(d.dir, "vici"))
	cmd := exec.CommandContext(ctx, d.swanctl, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "STRONGSWAN_CONF=" + filepath.Join(d.dir, "strongswan.conf")}
	var output commandOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if e := cmd.Run(); e != nil {
		result := strings.TrimSpace(output.String())
		if len(result) > 2048 {
			result = result[len(result)-2048:]
		}
		return "", fmt.Errorf("swanctl %s: %w: %s", args[0], e, result)
	}
	return output.String(), nil
}
func (d *daemon) alive() bool {
	if d.cmd == nil {
		return false
	}
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}
func (d *daemon) stop() error {
	if d.alive() {
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-d.done:
		case <-time.After(2 * time.Second):
			_ = d.cmd.Process.Kill()
			select {
			case <-d.done:
			case <-time.After(time.Second):
				return errors.New("charon did not stop")
			}
		}
	}
	d.cmd = nil
	return nil
}
func (d *daemon) probePorts() error {
	if d.alive() {
		return nil
	}
	for _, port := range []int{500, 4500} {
		for _, family := range []string{"udp4", "udp6"} {
			socket, e := net.ListenUDP(family, &net.UDPAddr{Port: port})
			if errors.Is(e, syscall.EAFNOSUPPORT) || errors.Is(e, syscall.EPROTONOSUPPORT) {
				continue
			}
			if e != nil {
				return fmt.Errorf("порт IKE UDP %d занят или недоступен: %w", port, e)
			}
			socket.Close()
		}
	}
	return nil
}
func (d *daemon) spawn(access *Tunnel) error {
	if e := d.probePorts(); e != nil {
		return e
	}
	conf := filepath.Join(d.dir, "strongswan.conf")
	plugins, radius := "", ""
	if access != nil {
		keyPath := os.Getenv("GFW_VPN_AUTH_KEY")
		if keyPath == "" {
			keyPath = identity.DefaultKey
		}
		key, err := identity.ReadKey(keyPath)
		if err != nil {
			return err
		}
		plugins = " md5 eap-identity eap-gtc eap-radius"
		radius = fmt.Sprintf(`
    eap-gtc {
      backend = radius
    }
    eap-radius {
      server = 127.0.0.1
      port = 18128
      secret = %s
      nas_identifier = %s
      sockets = 4
      retransmit_tries = 2
      retransmit_timeout = 2
    }
`, key, access.Auth.NAS(access.ID))
	}
	settings := fmt.Sprintf(`charon {
  load_modular = no
  load = random nonce sha1 sha2 hmac kdf pem x509 revocation constraints pkcs1 pkcs8 pubkey openssl kernel-netlink socket-default vici%s
  install_routes = no
  routing_table = 0
  install_virtual_ip = no
  threads = 8
  retransmit_tries = 3
  retransmit_timeout = 2
  plugins {
    vici {
      socket = unix://%s
    }
%s
  }
  filelog {
    stdout {
      default = 1
      time_format = %%Y-%%m-%%dT%%H:%%M:%%S
      flush_line = yes
    }
  }
}
`, plugins, filepath.Join(d.dir, "vici"), radius)
	if e := os.WriteFile(conf, []byte(settings), 0600); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join(d.dir, "vici")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	cmd := exec.Command(d.charon)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "STRONGSWAN_CONF=" + conf}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	cmd.Stdout, cmd.Stderr = &d.log, &d.log
	started := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		e := cmd.Start()
		started <- e
		if e == nil {
			_ = cmd.Wait()
		}
	}()
	if e := <-started; e != nil {
		return e
	}
	d.cmd, d.done = cmd, done
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && d.alive() {
		if _, e := d.command(500*time.Millisecond, "--stats"); e == nil {
			return nil
		}
		time.Sleep(75 * time.Millisecond)
	}
	return errors.Join(errors.New("charon не запустился; проверьте журнал IPsec"), d.stop())
}
func ikeName(t Tunnel) string { return "gfw-" + t.ID }
func (d *daemon) load(materials []Material, ifID func(Tunnel) uint32) error {
	stage := filepath.Join(d.dir, "credentials")
	if e := os.RemoveAll(stage); e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	for _, name := range []string{"x509", "x509ca", "x509crl", "private"} {
		if e := os.MkdirAll(filepath.Join(stage, name), 0700); e != nil {
			return e
		}
	}
	write := func(dir, name string, data []byte) error {
		return os.WriteFile(filepath.Join(stage, dir, name), data, 0600)
	}
	var conf, pools strings.Builder
	conf.WriteString("connections {\n")
	for _, m := range materials {
		t := m.Tunnel
		name := ikeName(t)
		own, e := vpncred.Leaf(m.Certificate)
		if e != nil {
			return e
		}
		if len(m.Peer) > 0 {
			peer, e := vpncred.Leaf(m.Peer)
			if e != nil {
				return e
			}
			if e = write("x509", name+"-peer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Raw})); e != nil {
				return e
			}
		}
		for _, f := range []struct {
			dir, name string
			raw       []byte
		}{
			{"x509", name + ".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: own.Raw})},
			{"private", name + ".pem", m.Key},
			{"x509ca", m.CAID + ".pem", m.CA},
			{"x509crl", m.CAID + ".pem", m.CRL},
		} {
			if e = write(f.dir, f.name, f.raw); e != nil {
				return e
			}
		}
		if t.Auth != nil {
			fmt.Fprintf(&pools, "  %s {\n    addrs = %s\n  }\n", name, t.RemoteNetworks[0])
			fmt.Fprintf(&conf, `  %[1]s {
    version = 2
    local_addrs = %[2]s
    remote_addrs = %%any
    pools = %[1]s
    mobike = no
    encap = yes
    proposals = aes256gcm16-prfsha256-ecp256
    send_cert = always
    local {
      auth = pubkey
      id = %[3]s
      certs = %[1]s.pem
    }
`, name, t.LocalAddress, IKEIdentity(t.PublicEndpoint))
			peerID := "%any"
			if t.Auth.Certificate {
				peerID = IKEIdentity(t.ClientUser)
				fmt.Fprintf(&conf, `    remote-cert {
      round = 0
      auth = pubkey
      id = %s
      certs = %s-peer.pem
      cacerts = %s.pem
      revocation = strict
    }
`, peerID, name, m.CAID)
			}
			fmt.Fprintf(&conf, `    remote-eap {
      round = 1
      auth = eap-gtc
      id = %[2]s
    }
    children {
      %[1]s {
        local_ts = %[3]s
        remote_ts = dynamic
        if_id_in = %[4]d
        if_id_out = %[4]d
        esp_proposals = aes256gcm16-ecp256
      }
    }
  }
`, name, peerID, strings.Join(t.LocalNetworks, ", "), ifID(t))
			continue
		}
		action := "none"
		if t.Initiate {
			action = "trap|start"
		}
		fmt.Fprintf(&conf, `  %[1]s {
    version = 2
    local_addrs = %[2]s
    remote_addrs = %[3]s
    mobike = no
    encap = yes
    proposals = aes256gcm16-prfsha256-ecp256
    send_cert = always
    dpd_delay = 20s
    local {
      auth = pubkey
      certs = %[1]s.pem
    }
    remote {
      auth = pubkey
      certs = %[1]s-peer.pem
      cacerts = %[4]s.pem
      revocation = strict
    }
    children {
      %[1]s {
        local_ts = %[5]s
        remote_ts = %[6]s
        if_id_in = %[7]d
        if_id_out = %[7]d
        esp_proposals = aes256gcm16-ecp256
        start_action = %[8]s
      }
    }
  }
`, name, t.LocalAddress, t.RemoteAddress, m.CAID, strings.Join(t.LocalNetworks, ", "), strings.Join(t.RemoteNetworks, ", "), ifID(t), action)
	}
	conf.WriteString("}\n")
	if pools.Len() > 0 {
		fmt.Fprintf(&conf, "pools {\n%s}\n", pools.String())
	}
	path := filepath.Join(stage, "swanctl.conf")
	if e := os.WriteFile(path, []byte(conf.String()), 0600); e != nil {
		return e
	}
	if _, e := d.command(5*time.Second, "--load-creds", "--file", path); e != nil {
		return e
	}
	if pools.Len() > 0 {
		if _, e := d.command(5*time.Second, "--load-pools", "--file", path); e != nil {
			return e
		}
	}
	if _, e := d.command(5*time.Second, "--load-conns", "--file", path); e != nil {
		return e
	}
	return nil
}
