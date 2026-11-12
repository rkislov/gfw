//go:build linux

package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkislov/gfw/internal/vpncred"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeProtocol = 243

type Linux struct {
	Vault                  *Vault
	LAN, Path, RuntimeRoot string
	processes              map[string]*process
	retry                  time.Time
	last                   RuntimeConfig
	lock                   *os.File
}
type process struct {
	done     chan struct{}
	cmd      *exec.Cmd
	writer   *logWriter
	config   string
	instance Instance
}
type logWriter struct {
	mu    sync.Mutex
	path  string
	ready bool
	tail  string
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	combined := w.tail + string(p)
	if len(combined) > 128 {
		w.tail = combined[len(combined)-128:]
	} else {
		w.tail = combined
	}
	if strings.Contains(combined, "Initialization Sequence Completed") {
		w.ready = true
	}
	if stat, e := os.Stat(w.path); e == nil && stat.Size()+int64(len(p)) > 1<<20 {
		_ = os.Remove(w.path + ".1")
		if e = os.Rename(w.path, w.path+".1"); e != nil {
			return 0, e
		}
	}
	f, e := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return 0, e
	}
	n, e := f.Write(p)
	return n, errors.Join(e, f.Close())
}
func (w *logWriter) isReady() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.ready }
func NewLinux(v *Vault, lan, path, root string) (*Linux, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(root) || strings.ContainsAny(root, " \t\r\n\"'\\") {
		return nil, errors.New("OpenVPN paths must be absolute")
	}
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("OpenVPN executable must be trusted and root-owned")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, path, "--version").Output()
	if e != nil || (!strings.HasPrefix(string(out), "OpenVPN 2.6.") && !strings.HasPrefix(string(out), "OpenVPN 2.7.")) {
		return nil, errors.New("OpenVPN 2.6/2.7 required")
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	info, e = os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("OpenVPN runtime directory must be private")
	}
	var fs unix.Statfs_t
	if e = unix.Statfs(root, &fs); e != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, errors.New("OpenVPN runtime secrets require tmpfs")
	}
	if len(filepath.Join(root, strings.Repeat("a", 32), "m.sock")) > 100 {
		return nil, errors.New("OpenVPN runtime path too long")
	}
	if e = os.MkdirAll(filepath.Join(v.root, "logs"), 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(root, "runtime.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("another agent owns OpenVPN runtime directory")
	}
	return &Linux{Vault: v, LAN: lan, Path: path, RuntimeRoot: root, processes: map[string]*process{}, lock: lock}, nil
}
func ownerGroup(i Instance) uint32 {
	s := sha256.Sum256([]byte("openvpn:" + i.ID))
	return binary.BigEndian.Uint32(s[:4]) | 0x80000000
}
func owned(l netlink.Link, i Instance) bool {
	return l.Type() == "tuntap" && l.Attrs().Alias == "gfw:openvpn:"+i.ID && l.Attrs().Group == ownerGroup(i)
}
func prefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a, bits), true
}
func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 32)}
}
func (l *Linux) guard(link netlink.Link) error {
	if link.Attrs().Name == l.LAN || link.Attrs().MasterIndex != 0 {
		return errors.New("защищённый LAN или зависимое сетевое устройство")
	}
	links, e := netlink.LinkList()
	if e != nil {
		return e
	}
	for _, v := range links {
		if v.Attrs().Index != link.Attrs().Index && (v.Attrs().ParentIndex == link.Attrs().Index && v.Type() != "veth" || v.Attrs().MasterIndex == link.Attrs().Index) {
			return errors.New("TUN используется внешним устройством")
		}
	}
	routes, e := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if e != nil {
		return e
	}
	for _, r := range routes {
		if r.Protocol != unix.RTPROT_KERNEL && r.Protocol != routeProtocol {
			return errors.New("на TUN есть чужие маршруты")
		}
		if r.Table != 0 && r.Table != unix.RT_TABLE_MAIN && r.Table != unix.RT_TABLE_LOCAL {
			return errors.New("TUN используется другой таблицей маршрутизации")
		}
	}
	return nil
}
func (l *Linux) Prepare(c, old RuntimeConfig) (Plan, error) {
	p := PreviewRuntime(c)
	if e := ValidateRuntime(c); e != nil {
		return p, e
	}
	links, e := netlink.LinkList()
	if e != nil {
		return p, e
	}
	for _, i := range old.Instances {
		link, e := netlink.LinkByName(i.Interface)
		if e == nil && owned(link, i) {
			if e = l.guard(link); e != nil {
				return p, e
			}
		}
	}
	known := map[string]Instance{}
	for _, cfg := range []RuntimeConfig{old, c} {
		for _, i := range cfg.Instances {
			known[i.Interface] = i
		}
	}
	for _, i := range c.Instances {
		if !i.Enabled {
			continue
		}
		if i.Interface == l.LAN {
			return p, errors.New("OpenVPN не может изменять LAN")
		}
		if reason, _ := l.Vault.blocked(i); reason != "" {
			return p, errors.New(reason)
		}
		network, _ := netip.ParsePrefix(i.Address)
		wanted := []netip.Prefix{network.Masked()}
		for _, s := range i.Routes {
			r, _ := netip.ParsePrefix(s)
			wanted = append(wanted, r)
		}
		bindFound := false
		for _, link := range links {
			if link.Attrs().Name == i.Interface {
				if !owned(link, i) {
					return p, errors.New("имя TUN занято чужим интерфейсом")
				}
				if e = l.guard(link); e != nil {
					return p, e
				}
			}
			skip := false
			if previous, ok := known[link.Attrs().Name]; ok && owned(link, previous) {
				skip = true
			}
			addresses, e := netlink.AddrList(link, netlink.FAMILY_V4)
			if e != nil {
				return p, e
			}
			for _, a := range addresses {
				other, ok := prefix(a.IPNet)
				if !ok {
					continue
				}
				if i.Mode == "server" && other.Addr().String() == i.BindAddress && link.Attrs().Flags&net.FlagUp != 0 {
					bindFound = true
				}
				if skip {
					continue
				}
				for _, r := range wanted {
					if r.Overlaps(other.Masked()) {
						return p, fmt.Errorf("подсеть VPN/маршрут пересекается с %s; доступ к LAN и underlay защищён", link.Attrs().Name)
					}
				}
			}
		}
		if i.Mode == "server" && !bindFound {
			return p, errors.New("bind-адрес OpenVPN не назначен включённому интерфейсу")
		}
		routes, e := netlink.RouteList(nil, netlink.FAMILY_V4)
		if e != nil {
			return p, e
		}
		for _, r := range routes {
			n, ok := prefix(r.Dst)
			if !ok || n.Bits() == 0 {
				continue
			}
			skip := false
			for _, link := range links {
				if link.Attrs().Index == r.LinkIndex {
					if prev, ok := known[link.Attrs().Name]; ok && owned(link, prev) {
						skip = true
					}
				}
			}
			if skip {
				continue
			}
			for _, w := range wanted {
				if w.Overlaps(n) {
					return p, errors.New("маршрут VPN пересекается с существующим маршрутом")
				}
			}
		}
	}
	p.CanApply = true
	return p, nil
}
func (l *Linux) CAs(c RuntimeConfig) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, i := range c.Instances {
		b, e := l.Vault.Material(i)
		if e == nil && !seen[b.CAID] {
			seen[b.CAID] = true
			out = append(out, b.CAID)
		}
	}
	return out
}
func (l *Linux) Stage(all []Material, active RuntimeConfig) error {
	if len(all) > 4 {
		return errors.New("too many OpenVPN materials")
	}
	updates := []CRLUpdate{}
	for _, b := range all {
		if e := validateMaterial(b); e != nil {
			return e
		}
		if old, e := l.Vault.Material(b.Instance); e == nil {
			if !bytes.Equal(old.CA, b.CA) || !bytes.Equal(old.Certificate, b.Certificate) || !bytes.Equal(old.Key, b.Key) || old.CAID != b.CAID || !reflect.DeepEqual(old.Peers, b.Peers) {
				return errors.New("immutable OpenVPN certificate material changed")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e := l.Vault.put(Ref(b.Instance)+".bundle", b); e != nil {
			return e
		}
		updates = append(updates, CRLUpdate{b.CAID, b.CA, b.CRL})
	}
	return l.Refresh(updates, active)
}
func (l *Linux) Refresh(updates []CRLUpdate, active RuntimeConfig) error {
	changed := false
	var first error
	for _, u := range updates {
		v, e := l.Vault.SaveCRL(u)
		changed = changed || v
		first = errors.Join(first, e)
	}
	// Persisting revocation takes priority over transaction rollback. Restart all
	// managed sessions after any CRL change, including during a pending apply.
	if changed {
		first = errors.Join(first, l.Activate(active, active))
	}
	return first
}
func (l *Linux) dir(i Instance) string { return filepath.Join(l.RuntimeRoot, i.ID) }
func management(path, command string) (string, error) {
	conn, e := net.DialTimeout("unix", path, 500*time.Millisecond)
	if e != nil {
		return "", e
	}
	defer conn.Close()
	return managementCommand(conn, command, false)
}

func managementCommand(conn net.Conn, command string, singleReply bool) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return "", err
	}
	if _, e := io.WriteString(conn, command+"\n"); e != nil {
		return "", e
	}
	scan := bufio.NewScanner(io.LimitReader(conn, 128<<10))
	scan.Buffer(make([]byte, 1024), 64<<10)
	var out strings.Builder
	for scan.Scan() {
		line := scan.Text()
		if singleReply {
			switch {
			case strings.HasPrefix(line, "SUCCESS:"):
				return line, nil
			case strings.HasPrefix(line, "ERROR:"):
				return "", fmt.Errorf("OpenVPN: %s", line)
			}
		}
		if line == "END" && !singleReply {
			return out.String(), nil
		}
		if !strings.HasPrefix(line, ">") {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	if e := scan.Err(); e != nil {
		return out.String(), e
	}
	return out.String(), errors.New("incomplete OpenVPN management response")
}

func (l *Linux) stop(i Instance) error {
	if p := l.processes[i.ID]; p != nil {
		select {
		case <-p.done:
		default:
			p.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
				p.cmd.Process.Kill()
				<-p.done
			}
		}
		delete(l.processes, i.ID)
	} else {
		path := filepath.Join(l.dir(i), "m.sock")
		if conn, e := net.DialTimeout("unix", path, 200*time.Millisecond); e == nil {
			conn.SetDeadline(time.Now().Add(time.Second))
			io.WriteString(conn, "signal SIGTERM\n")
			conn.Close()
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				c, e := net.DialTimeout("unix", path, 100*time.Millisecond)
				if e != nil {
					break
				}
				c.Close()
				time.Sleep(50 * time.Millisecond)
			}
			if c, e := net.DialTimeout("unix", path, 100*time.Millisecond); e == nil {
				c.Close()
				return errors.New("old OpenVPN process still running")
			}
		}
	}
	return os.RemoveAll(l.dir(i))
}
func (l *Linux) remove(i Instance) error {
	link, e := netlink.LinkByName(i.Interface)
	if _, ok := e.(netlink.LinkNotFoundError); ok {
		return nil
	}
	if e != nil {
		return e
	}
	if !owned(link, i) {
		return nil // Never delete a foreign link, including during compensation.
	}
	if e = l.guard(link); e != nil {
		return e
	}
	return netlink.LinkDel(link)
}
func (l *Linux) create(i Instance) error {
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	req, e := unix.NewIfreq(i.Interface)
	if e != nil {
		return e
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, req); e != nil {
		return e
	}
	link, e := netlink.LinkByName(i.Interface)
	if e != nil {
		return e
	}
	if e = netlink.LinkSetAlias(link, "gfw:openvpn:"+i.ID); e != nil {
		return e
	}
	if e = netlink.LinkSetGroup(link, int(ownerGroup(i))); e != nil {
		return e
	}
	// Until this point the fd owns a nonpersistent TUN. A crash deletes it. Only
	// after both ownership markers exist may it survive for child/recovery use.
	if e = unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); e != nil {
		return e
	}
	n, _ := netip.ParsePrefix(i.Address)
	if e = netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet(n)}); e != nil {
		return e
	}
	if e = netlink.LinkSetUp(link); e != nil {
		return e
	}
	for _, s := range i.Routes {
		r, _ := netip.ParsePrefix(s)
		if e = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet(r), Protocol: routeProtocol, Priority: 100, Table: unix.RT_TABLE_MAIN}); e != nil {
			return e
		}
	}
	return nil
}
func fp(raw []byte) string {
	c, _ := vpncred.Leaf(raw)
	s := sha256.Sum256(c.Raw)
	h := hex.EncodeToString(s[:])
	v := []string{}
	for n := 0; n < len(h); n += 2 {
		v = append(v, h[n:n+2])
	}
	return strings.Join(v, ":")
}
func (l *Linux) configuration(i Instance) (string, error) {
	b, e := l.Vault.Material(i)
	if e != nil {
		return "", e
	}
	u, e := l.Vault.CRL(b.CAID)
	if e != nil {
		return "", e
	}
	r, e := vpncred.ParseCRL(u)
	if e != nil {
		return "", e
	}
	dir := l.dir(i)
	if e = os.MkdirAll(filepath.Join(dir, "ccd"), 0700); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dir, "crl.pem"), u.CRL, 0600); e != nil {
		return "", e
	}
	proto := i.Protocol
	if i.Protocol == "tcp" {
		proto = "tcp-server"
		if i.Mode == "client" {
			proto = "tcp-client"
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "dev %s\ndev-type tun\nproto %s\ntopology subnet\nifconfig-noexec\nroute-noexec\nscript-security 1\ndisable-dco\nauth-nocache\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\nallow-compression no\nverb 3\nmanagement %s unix\ncrl-verify %s\n", i.Interface, proto, filepath.Join(dir, "m.sock"), filepath.Join(dir, "crl.pem"))
	if i.Mode == "server" {
		n, _ := netip.ParsePrefix(i.Address)
		mask := net.IP(net.CIDRMask(n.Bits(), 32)).String()
		cert := i.Auth == nil || i.Auth.Certificate
		fmt.Fprintf(&out, "mode server\ntls-server\nifconfig %s %s\nlocal %s\nport %d\ndh none\nclient-config-dir %s\nccd-exclusive\npush \"topology subnet\"\npush \"route-gateway %s\"\nkeepalive 10 60\nmax-clients 256\n", n.Addr(), mask, i.BindAddress, i.Port, filepath.Join(dir, "ccd"), n.Addr())
		if i.Auth != nil && i.Auth.Credentials() {
			fmt.Fprintf(&out, "script-security 2\ntmp-dir %s\nauth-user-pass-verify \"/usr/sbin/gfw-agent vpn-auth %s %s\" via-file\nauth-gen-token 28800\n", dir, i.ID, i.Auth.Arguments())
		}
		if cert {
			out.WriteString("remote-cert-tls client\n<peer-fingerprint>\n")
		} else {
			out.WriteString("verify-client-cert none\nusername-as-common-name\n")
		}
		count := 0
		for _, p := range i.Clients {
			cn := p.Username
			if cert {
				raw := b.Peers[p.CertificateID]
				c, e := vpncred.Leaf(raw)
				if e != nil {
					return "", e
				}
				if !vpncred.UsableCert(c, r) {
					continue
				}
				cn = c.Subject.CommonName
				if !regexpCN.MatchString(cn) || cn == "DEFAULT" {
					return "", errors.New("invalid client CN")
				}
				fmt.Fprintln(&out, fp(raw))
			}
			if e = os.WriteFile(filepath.Join(dir, "ccd", cn), []byte(fmt.Sprintf("ifconfig-push %s %s\n", p.Address, mask)), 0600); e != nil {
				return "", e
			}
			count++
		}
		if cert {
			if count == 0 {
				fmt.Fprintln(&out, strings.TrimSuffix(strings.Repeat("00:", 32), ":"))
			}
			out.WriteString("</peer-fingerprint>\n")
		}
	} else {
		fmt.Fprintf(&out, "client\nremote %s %d\nnobind\nroute-nopull\npull-filter ignore redirect-gateway\nremote-cert-tls server\npeer-fingerprint %s\n", i.Remote, i.Port, fp(b.Peers[i.ServerCertificateID]))
	}
	for _, p := range []struct {
		name string
		raw  []byte
	}{{"ca", b.CA}, {"cert", b.Certificate}, {"key", b.Key}} {
		fmt.Fprintf(&out, "<%s>\n%s\n</%s>\n", p.name, strings.TrimSpace(string(p.raw)), p.name)
	}
	return out.String(), nil
}
func (l *Linux) start(i Instance) error {
	cfg, e := l.configuration(i)
	if e != nil {
		return e
	}
	path := filepath.Join(l.dir(i), "instance.conf")
	if e = os.WriteFile(path, []byte(cfg), 0600); e != nil {
		return e
	}
	writer := &logWriter{path: filepath.Join(l.Vault.root, "logs", i.ID+".log")}
	p := &process{done: make(chan struct{}), writer: writer, config: Ref(i), instance: i}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		cmd := exec.Command(l.Path, "--config", path)
		cmd.Stdout = writer
		cmd.Stderr = writer
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
		p.cmd = cmd
		e := cmd.Start()
		started <- e
		if e == nil {
			_ = cmd.Wait()
		}
		close(p.done)
	}()
	if e = <-started; e != nil {
		return e
	}
	l.processes[i.ID] = p
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			return errors.New("OpenVPN exited; see instance logs")
		default:
		}
		if writer.isReady() {
			if i.Mode == "server" {
				return nil
			}
			state, e := management(filepath.Join(l.dir(i), "m.sock"), "state")
			a, _ := netip.ParsePrefix(i.Address)
			if e == nil && strings.Contains(state, ",CONNECTED,SUCCESS,"+a.Addr().String()+",") {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if i.Mode == "client" {
		select {
		case <-p.done:
		default:
			return nil
		}
	}
	return errors.New("OpenVPN readiness timeout; see logs")
}
func (l *Linux) Activate(c, old RuntimeConfig) error {
	l.last = RuntimeConfig{Instances: append(append([]Instance{}, c.Instances...), old.Instances...)}
	if e := ValidateRuntime(c); e != nil {
		return e
	}
	seen := map[string]Instance{}
	for _, cfg := range []RuntimeConfig{old, c} {
		for _, i := range cfg.Instances {
			seen[i.ID+":"+i.Interface] = i
		}
	}
	// Stop all known children before touching their persistent TUNs.
	stopped := map[string]bool{}
	for _, i := range seen {
		if !stopped[i.ID] {
			if e := l.stop(i); e != nil {
				return e
			}
			stopped[i.ID] = true
		}
	}
	for _, i := range seen {
		if e := l.remove(i); e != nil {
			return e
		}
	}
	for _, i := range c.Instances {
		if !i.Enabled {
			continue
		}
		if why, _ := l.Vault.blocked(i); why != "" {
			continue
		}
		if e := l.create(i); e != nil {
			return e
		}
		if e := l.start(i); e != nil {
			return e
		}
	}
	return nil
}
func (l *Linux) runtimeCRL(i Instance) bool {
	b, e := l.Vault.Material(i)
	if e != nil {
		return false
	}
	u, e := l.Vault.CRL(b.CAID)
	if e != nil {
		return false
	}
	raw, e := os.ReadFile(filepath.Join(l.dir(i), "crl.pem"))
	return e == nil && bytes.Equal(raw, u.CRL)
}
func (l *Linux) Verify(c RuntimeConfig) error {
	for _, i := range c.Instances {
		p := l.processes[i.ID]
		if !i.Enabled {
			if p != nil {
				return errors.New("disabled OpenVPN process remains")
			}
			continue
		}
		if why, _ := l.Vault.blocked(i); why != "" {
			if p != nil {
				return errors.New("blocked OpenVPN still running")
			}
			continue
		}
		if p == nil || p.config != Ref(i) || !p.writer.isReady() || !l.runtimeCRL(i) {
			return errors.New("OpenVPN process not ready")
		}
		select {
		case <-p.done:
			return errors.New("OpenVPN process exited")
		default:
		}
		link, e := netlink.LinkByName(i.Interface)
		if e != nil || !owned(link, i) || link.Attrs().Flags&net.FlagUp == 0 {
			return errors.New("owned TUN missing or down")
		}
		if e = l.guard(link); e != nil {
			return e
		}
		addresses, e := netlink.AddrList(link, netlink.FAMILY_V4)
		if e != nil {
			return e
		}
		found := false
		for _, a := range addresses {
			n, ok := prefix(a.IPNet)
			if ok && n.String() == i.Address {
				found = true
			}
		}
		if !found || len(addresses) != 1 {
			return errors.New("TUN address drift")
		}
		for _, s := range i.Routes {
			routes, e := netlink.RouteList(link, netlink.FAMILY_V4)
			if e != nil {
				return e
			}
			found := false
			for _, r := range routes {
				n, ok := prefix(r.Dst)
				if ok && n.String() == s && r.Protocol == routeProtocol {
					found = true
				}
			}
			if !found {
				return errors.New("TUN route drift")
			}
		}
		state, e := management(filepath.Join(l.dir(i), "m.sock"), "state")
		if e != nil {
			return e
		}
		if i.Mode == "client" {
			a, _ := netip.ParsePrefix(i.Address)
			if !strings.Contains(state, ",CONNECTED,SUCCESS,"+a.Addr().String()+",") {
				return errors.New("OpenVPN client disconnected or address mismatch")
			}
		}
	}
	return nil
}
func (l *Linux) Status(c RuntimeConfig) ([]Status, error) {
	out := []Status{}
	for _, i := range c.Instances {
		s := Status{ID: i.ID, Interface: i.Interface, Mode: i.Mode, Sessions: []Session{}}
		s.Blocked, s.CRLNumber = l.Vault.blocked(i)
		if p := l.processes[i.ID]; p != nil {
			select {
			case <-p.done:
			default:
				s.Running = true
				s.Ready = p.writer.isReady()
				s.State, _ = management(filepath.Join(l.dir(i), "m.sock"), "state")
				if i.Mode == "client" {
					a, _ := netip.ParsePrefix(i.Address)
					s.Ready = s.Ready && strings.Contains(s.State, ",CONNECTED,SUCCESS,"+a.Addr().String()+",")
				}
				raw, err := management(filepath.Join(l.dir(i), "m.sock"), "status 3")
				s.SessionsError = err != nil
				s.Sessions = parseSessions(raw)
			}
		}
		out = append(out, s)
	}
	return out, nil
}
func (l *Linux) Disconnect(instance Instance, id uint32, user string) error {
	conn, err := net.DialTimeout("unix", filepath.Join(l.dir(instance), "m.sock"), 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	raw, err := managementCommand(conn, "status 3", false)
	if err != nil {
		return err
	}
	for _, session := range parseSessions(raw) {
		if session.ClientID != nil && *session.ClientID == id && session.User() == user {
			_, err = managementCommand(conn, fmt.Sprintf("client-kill %d", id), true)
			return err
		}
	}
	return vpncred.ErrSessionGone
}

func (l *Linux) Logs(id string) ([]string, error) {
	if !IDPattern.MatchString(id) {
		return nil, errors.New("invalid instance ID")
	}
	raw, e := os.ReadFile(filepath.Join(l.Vault.root, "logs", id+".log"))
	if errors.Is(e, os.ErrNotExist) {
		return []string{}, nil
	}
	if e != nil {
		return nil, e
	}
	if len(raw) > 64<<10 {
		raw = raw[len(raw)-(64<<10):]
	}
	out := []string{}
	scan := bufio.NewScanner(strings.NewReader(string(raw)))
	scan.Buffer(make([]byte, 1024), 64<<10)
	for scan.Scan() {
		line := scan.Text()
		if len(line) > 1000 {
			line = line[:1000]
		}
		out = append(out, line)
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out, nil
}
func (l *Linux) Maintain(c RuntimeConfig) error {
	for _, i := range c.Instances {
		if !i.Enabled {
			continue
		}
		if why, _ := l.Vault.blocked(i); l.processes[i.ID] != nil && (why != "" || !l.runtimeCRL(i)) {
			if e := l.stop(i); e != nil {
				return e
			}
			if e := l.remove(i); e != nil {
				return e
			}
		}
	}
	if time.Now().Before(l.retry) {
		return nil
	}
	l.retry = time.Now().Add(30 * time.Second)
	for _, i := range c.Instances {
		if !i.Enabled {
			continue
		}
		if why, _ := l.Vault.blocked(i); why != "" {
			continue
		}
		p := l.processes[i.ID]
		dead := p == nil
		if p != nil {
			select {
			case <-p.done:
				dead = true
			default:
			}
		}
		if dead {
			if _, e := l.Prepare(RuntimeConfig{Instances: []Instance{i}}, c); e != nil {
				return e
			}
			if e := l.stop(i); e != nil {
				return e
			}
			if e := l.remove(i); e != nil {
				return e
			}
			if e := l.create(i); e != nil {
				return e
			}
			return l.start(i)
		}
	}
	return nil
}

func (l *Linux) Close() error {
	e := l.Activate(RuntimeEmpty(), l.last)
	if l.lock != nil {
		e = errors.Join(e, l.lock.Close())
		l.lock = nil
	}
	return e
}
