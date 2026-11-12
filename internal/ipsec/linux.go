//go:build linux

package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/vpncred"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeProtocol = 244

type Linux struct {
	daemon *daemon
	vault  *vpncred.Vault
	lan    string
	loaded map[string]bool
	last   Config
	retry  time.Time
}

func NewLinux(v *vpncred.Vault, lan, charon, swanctl, dir string) (Backend, error) {
	d, e := newDaemon(charon, swanctl, dir)
	if e != nil {
		return nil, e
	}
	return &Linux{daemon: d, vault: v, lan: lan}, nil
}
func xfrmID(t Tunnel) uint32 {
	hash := sha256.Sum256([]byte("gfw-ipsec:" + t.ID))
	return 0x47000000 | binary.BigEndian.Uint32(hash[:4])&0x00ffffff
}
func alias(t Tunnel) string { return "gfw:ipsec:" + t.ID }
func owned(link netlink.Link, t Tunnel) bool {
	x, ok := link.(*netlink.Xfrmi)
	return ok && x.Ifid == xfrmID(t) && x.Name == t.Interface && x.Group == xfrmID(t) && (x.Alias == alias(t) || x.Alias == "")
}
func union(a, b Config) []Tunnel {
	list := append(append([]Tunnel{}, a.Tunnels...), b.Tunnels...)
	seen := map[string]bool{}
	out := []Tunnel{}
	for _, t := range list {
		key := t.ID + "/" + t.Interface
		if t.Enabled && !seen[key] {
			seen[key] = true
			out = append(out, t)
		}
	}
	return out
}
func routePrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), bits).Masked(), true
}
func (l *Linux) material(t Tunnel) (Material, error) {
	var b Material
	if e := l.vault.Get(ref(t), &b); e != nil {
		return b, errors.New("сертификаты туннеля не доставлены")
	}
	update, e := l.vault.CRL(b.CAID)
	if e != nil {
		return b, errors.New("CRL туннеля не доставлен")
	}
	if e = checkCertificates(b, update); e != nil {
		return b, e
	}
	b.CRL = update.CRL
	return b, nil
}
func (l *Linux) CAs(c Config) []string {
	found := map[string]bool{}
	out := []string{}
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		var b Material
		if l.vault.Get(ref(t), &b) == nil && !found[b.CAID] {
			found[b.CAID] = true
			out = append(out, b.CAID)
		}
	}
	return out
}
func (l *Linux) Stage(all []Material, active Config) error {
	if len(all) > 8 {
		return errors.New("слишком много комплектов сертификатов")
	}
	updates := []vpncred.CRLUpdate{}
	for _, b := range all {
		if e := ValidateMaterial(b); e != nil {
			return e
		}
		var old Material
		if e := l.vault.Get(ref(b.Tunnel), &old); e == nil {
			if !bytes.Equal(old.Key, b.Key) || !bytes.Equal(old.Certificate, b.Certificate) || !bytes.Equal(old.Peer, b.Peer) || !bytes.Equal(old.CA, b.CA) || old.CAID != b.CAID {
				return errors.New("изменились неизменяемые материалы сертификата")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		updates = append(updates, vpncred.CRLUpdate{CAID: b.CAID, CA: b.CA, CRL: b.CRL})
	}
	if e := l.Refresh(updates, active); e != nil {
		return e
	}
	for _, b := range all {
		b.CRL = nil
		if e := l.vault.Put(ref(b.Tunnel), b); e != nil {
			return e
		}
	}
	return nil
}
func (l *Linux) Refresh(updates []vpncred.CRLUpdate, active Config) error {
	if len(updates) > 16 {
		return errors.New("слишком много CRL")
	}
	needed := map[string]bool{}
	for _, id := range l.CAs(active) {
		needed[id] = true
	}
	changed := false
	var result error
	for _, u := range updates {
		updated, e := l.vault.SaveCRL(u)
		result = errors.Join(result, e)
		if updated && needed[u.CAID] {
			changed = true
		}
	}
	if changed {
		result = errors.Join(result, l.Activate(active, active))
	}
	return result
}

func (l *Linux) Prepare(c, old Config) (Plan, error) {
	plan := Preview(c)
	if e := Validate(c); e != nil {
		return plan, e
	}
	for _, t := range c.Tunnels {
		if t.Enabled {
			if _, e := l.material(t); e != nil {
				return plan, fmt.Errorf("%s: %w", t.Name, e)
			}
		}
	}
	if e := l.checkNetwork(c, old); e != nil {
		return plan, e
	}
	if len(Active(c)) > 0 {
		if e := l.daemon.probePorts(); e != nil {
			return plan, e
		}
	}
	plan.CanApply = true
	return plan, nil
}

func (l *Linux) checkNetwork(c, old Config) error {
	if len(union(c, old)) == 0 {
		return nil
	}
	links, e := netlink.LinkList()
	if e != nil {
		return e
	}
	known := union(c, old)
	ownIndex := map[int]bool{}
	ownID := map[uint32]bool{}
	byName := map[string]netlink.Link{}
	for _, link := range links {
		byName[link.Attrs().Name] = link
		for _, t := range known {
			if owned(link, t) {
				ownIndex[link.Attrs().Index] = true
				ownID[xfrmID(t)] = true
			}
		}
	}
	routes, e := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if e != nil {
		return e
	}
	for _, link := range links {
		a := link.Attrs()
		if ownIndex[a.Index] && (a.MasterIndex != 0 || a.Name == l.lan) {
			return errors.New("защищённый или занятый XFRM-интерфейс")
		}
		if !ownIndex[a.Index] && (ownIndex[a.MasterIndex] || link.Type() != "veth" && ownIndex[a.ParentIndex]) {
			return errors.New("XFRM-интерфейс используется другим устройством")
		}
	}
	for _, r := range routes {
		if ownIndex[r.LinkIndex] && r.Protocol != routeProtocol && r.Protocol != unix.RTPROT_KERNEL {
			return errors.New("на XFRM-интерфейсе есть посторонние маршруты")
		}
	}
	if len(Active(c)) == 0 {
		return nil
	}
	policies, e := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if e != nil {
		return fmt.Errorf("ядро XFRM: %w", e)
	}
	states, e := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if e != nil {
		return fmt.Errorf("ядро XFRM: %w", e)
	}
	addresses := map[string]bool{}
	var localNetworks []netip.Prefix
	for _, link := range links {
		if ownIndex[link.Attrs().Index] {
			continue
		}
		entries, e := netlink.AddrList(link, netlink.FAMILY_V4)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if entry.IPNet == nil {
				continue
			}
			if link.Attrs().Flags&net.FlagUp != 0 {
				addresses[entry.IP.String()] = true
			}
			if p, ok := routePrefix(entry.IPNet); ok {
				localNetworks = append(localNetworks, p)
			}
		}
	}
	ids := map[uint32]bool{}
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		if t.Interface == l.lan {
			return errors.New("XFRM не может использовать имя LAN")
		}
		id := xfrmID(t)
		if ids[id] {
			return errors.New("совпали идентификаторы XFRM")
		}
		ids[id] = true
		if link := byName[t.Interface]; link != nil && !owned(link, t) {
			return errors.New("имя XFRM-интерфейса занято")
		}
		for _, link := range links {
			if x, ok := link.(*netlink.Xfrmi); ok && x.Ifid == id && (!ownIndex[x.Index] || x.Alias != "" && x.Alias != alias(t)) {
				return errors.New("ID XFRM занят другим интерфейсом")
			}
		}
		if !ownID[id] {
			for _, policy := range policies {
				if uint32(policy.Ifid) == id {
					return errors.New("ID XFRM занят посторонней политикой")
				}
			}
			for _, state := range states {
				if uint32(state.Ifid) == id {
					return errors.New("ID XFRM занят посторонней SA")
				}
			}
		}
		if !addresses[t.LocalAddress] {
			return fmt.Errorf("локальный адрес IKE %s не назначен активному интерфейсу", t.LocalAddress)
		}
		for _, s := range t.RemoteNetworks {
			p := netip.MustParsePrefix(s)
			for _, local := range localNetworks {
				if p.Overlaps(local) {
					return errors.New("удалённая сеть пересекается с локальной сетью, включая LAN")
				}
			}
			for _, r := range routes {
				if ownIndex[r.LinkIndex] {
					continue
				}
				if rp, ok := routePrefix(r.Dst); ok && rp.Bits() > 0 && p.Overlaps(rp) {
					return fmt.Errorf("удалённая сеть %s пересекается с существующим маршрутом", p)
				}
			}
		}
	}
	return nil
}

func clearXFRM(id uint32) error {
	policies, e := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if e != nil {
		return e
	}
	for _, p := range policies {
		if uint32(p.Ifid) == id {
			if e = netlink.XfrmPolicyDel(&p); e != nil && !errors.Is(e, unix.ENOENT) {
				return e
			}
		}
	}
	states, e := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if e != nil {
		return e
	}
	for _, s := range states {
		if uint32(s.Ifid) == id {
			if e = netlink.XfrmStateDel(&s); e != nil && !errors.Is(e, unix.ESRCH) {
				return e
			}
		}
	}
	return nil
}
func getLink(t Tunnel) (netlink.Link, error) {
	link, e := netlink.LinkByName(t.Interface)
	var missing netlink.LinkNotFoundError
	if errors.As(e, &missing) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !owned(link, t) {
		return nil, nil
	}
	return link, nil
}

func (l *Linux) Activate(c, old Config) (err error) {
	if e := Validate(c); e != nil {
		return e
	}
	if e := l.daemon.stop(); e != nil {
		return e
	}
	l.loaded = nil
	if e := l.checkNetwork(c, old); e != nil {
		return e
	}
	l.last = Config{Tunnels: union(c, old)}
	defer func() {
		if err != nil {
			err = errors.Join(err, l.daemon.stop())
		}
	}()
	desired := Active(c)
	for _, t := range l.last.Tunnels {
		link, e := getLink(t)
		if e != nil {
			return e
		}
		if link == nil {
			continue
		}
		if e = clearXFRM(xfrmID(t)); e != nil {
			return e
		}
		next, keep := desired[t.Interface]
		if !keep || next.ID != t.ID {
			if e = netlink.LinkDel(link); e != nil {
				return e
			}
		}
	}
	materials := []Material{}
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		if e := ensureLink(t); e != nil {
			return e
		}
		if b, e := l.material(t); e == nil {
			materials = append(materials, b)
		}
	}
	l.last = c
	if len(materials) == 0 {
		return nil
	}
	var access *Tunnel
	for _, material := range materials {
		if material.Tunnel.Auth != nil {
			t := material.Tunnel
			access = &t
			break
		}
	}
	if e := l.daemon.spawn(access); e != nil {
		return e
	}
	if e := l.daemon.load(materials, xfrmID); e != nil {
		return e
	}
	l.loaded = map[string]bool{}
	for _, m := range materials {
		l.loaded[m.Tunnel.ID] = true
	}
	return nil
}
func ensureLink(t Tunnel) error {
	link, e := getLink(t)
	if e != nil {
		return e
	}
	if link == nil {
		link = &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: t.Interface, Group: xfrmID(t), MTU: 1400, TxQLen: -1}, Ifid: xfrmID(t)}
		if e = netlink.LinkAdd(link); e != nil {
			return fmt.Errorf("создание XFRM (проверьте CONFIG_XFRM_INTERFACE): %w", e)
		}
		link, e = netlink.LinkByName(t.Interface)
		if e != nil {
			return e
		}
	}
	if e = netlink.LinkSetAlias(link, alias(t)); e != nil {
		return e
	}
	if e = netlink.LinkSetUp(link); e != nil {
		return e
	}
	routes, e := netlink.RouteList(link, netlink.FAMILY_V4)
	if e != nil {
		return e
	}
	wanted := map[string]bool{}
	for _, s := range t.RemoteNetworks {
		wanted[s] = true
	}
	for _, r := range routes {
		if r.Protocol != routeProtocol {
			continue
		}
		p, ok := routePrefix(r.Dst)
		if ok && wanted[p.String()] {
			delete(wanted, p.String())
			continue
		}
		if e = netlink.RouteDel(&r); e != nil {
			return e
		}
	}
	for s := range wanted {
		p := netip.MustParsePrefix(s)
		dst := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 32)}
		if e = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK, Protocol: routeProtocol, Table: unix.RT_TABLE_MAIN}); e != nil {
			return e
		}
	}
	return nil
}

func (l *Linux) Verify(c Config) error {
	var eligible []Tunnel
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		link, e := getLink(t)
		if e != nil {
			return e
		}
		if link == nil || link.Attrs().Flags&net.FlagUp == 0 {
			return fmt.Errorf("XFRM-интерфейс %s недоступен", t.Interface)
		}
		routes, e := netlink.RouteList(link, netlink.FAMILY_V4)
		if e != nil {
			return e
		}
		for _, s := range t.RemoteNetworks {
			found := false
			for _, r := range routes {
				if p, ok := routePrefix(r.Dst); ok && p.String() == s && r.Protocol == routeProtocol && r.Gw == nil {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("маршрут IPsec %s отсутствует", s)
			}
		}
		if _, e := l.material(t); e == nil {
			eligible = append(eligible, t)
		} else if l.loaded[t.ID] && l.daemon.alive() {
			return e
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	if !l.daemon.alive() {
		return errors.New("процесс charon остановлен")
	}
	output, e := l.daemon.command(2*time.Second, "--list-conns")
	if e != nil {
		return e
	}
	for _, t := range eligible {
		if !strings.Contains("\n"+output, "\n"+ikeName(t)+":") {
			return fmt.Errorf("конфигурация IPsec %s не загружена", t.Name)
		}
	}
	return nil
}
func (l *Linux) Status(c Config) ([]Status, error) {
	out := []Status{}
	var sessionOutput string
	var err error
	if l.daemon.alive() {
		sessionOutput, err = l.daemon.command(2*time.Second, "--list-sas")
	}
	sessions := map[string]string{}
	name := ""
	for _, line := range strings.Split(sessionOutput, "\n") {
		if strings.HasPrefix(line, "gfw-") {
			name, _, _ = strings.Cut(line, ":")
		}
		if name != "" {
			sessions[name] += line + "\n"
		}
	}
	for _, t := range c.Tunnels {
		status := Status{ID: t.ID, Loaded: l.daemon.alive() && l.loaded[t.ID]}
		if t.Enabled {
			b, e := l.material(t)
			if e != nil {
				status.Blocked = e.Error()
			}
			if b.CAID != "" {
				if u, e := l.vault.CRL(b.CAID); e == nil {
					if crl, e := vpncred.ParseCRL(u); e == nil {
						status.CRLNumber = crl.Number.Int64()
					}
				}
			}
		}
		status.Details = strings.TrimSpace(sessions[ikeName(t)])
		status.Sessions = establishedPeers(status.Details)
		status.Established = len(status.Sessions) > 0
		out = append(out, status)
	}
	return out, err
}
func (l *Linux) Logs() ([]string, error) { return l.daemon.log.Lines(), nil }
func (l *Linux) Maintain(c Config) error {
	mustStop := false
	needsStart := false
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		_, e := l.material(t)
		loaded := l.loaded[t.ID] && l.daemon.alive()
		mustStop = mustStop || e != nil && loaded
		needsStart = needsStart || e == nil && !loaded
	}
	if mustStop {
		if e := l.daemon.stop(); e != nil {
			return e
		}
	}
	if mustStop || needsStart && time.Now().After(l.retry) {
		l.retry = time.Now().Add(10 * time.Second)
		return l.Activate(c, c)
	}
	return nil
}
func (l *Linux) Close() error {
	defer l.daemon.lock.Close()
	if e := l.daemon.stop(); e != nil {
		return e
	}
	var result error
	for _, t := range l.last.Tunnels {
		if !t.Enabled {
			continue
		}
		link, e := getLink(t)
		if e == nil && link != nil {
			e = clearXFRM(xfrmID(t))
		}
		result = errors.Join(result, e)
	}
	return result
}
