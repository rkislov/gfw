//go:build linux

package xdpguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Linux struct {
	active   map[string]attachment
	counters *ebpf.Map
	mode     string
}
type attachment struct {
	link.Link
	index     int
	programID ebpf.ProgramID
}

func New() Backend { return &Linux{} }

func (b *Linux) interfaces(c Config, lan string) ([]netlink.Link, error) {
	if len(c.Interfaces) == 0 {
		return nil, nil
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]netlink.Link, len(links))
	graph := make(map[int][]int, len(links))
	for _, l := range links {
		byName[l.Attrs().Name] = l
	}
	addEdge := func(a, z int) {
		if z > 0 && z != a {
			graph[a] = append(graph[a], z)
			graph[z] = append(graph[z], a)
		}
	}
	for _, l := range links {
		a := l.Attrs()
		addEdge(a.Index, a.MasterIndex)
		// A veth's IFLA_LINK denotes its peer, not a lower device.
		if l.Type() != "veth" && a.NetNsID < 0 {
			addEdge(a.Index, a.ParentIndex)
		}
		entries, err := os.ReadDir(filepath.Join("/sys/class/net", a.Name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			lower, ok := strings.CutPrefix(e.Name(), "lower_")
			if under := byName[lower]; ok && under != nil {
				addEdge(a.Index, under.Attrs().Index)
			}
		}
	}
	protected := map[int]bool{}
	management := byName[lan]
	if management == nil || management.Attrs().Flags&net.FlagUp == 0 {
		return nil, errors.New("интерфейс управления LAN недоступен")
	}
	todo := []int{management.Attrs().Index}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if !protected[id] {
			protected[id] = true
			todo = append(todo, graph[id]...)
		}
	}
	out := make([]netlink.Link, 0, len(c.Interfaces))
	for _, name := range c.Interfaces {
		l := byName[name]
		if l == nil {
			return nil, fmt.Errorf("WAN-интерфейс %s не найден", name)
		}
		a := l.Attrs()
		if protected[a.Index] {
			return nil, fmt.Errorf("%s связан с интерфейсом управления LAN %s", name, lan)
		}
		if a.Flags&net.FlagUp == 0 || a.Flags&net.FlagLoopback != 0 || len(a.HardwareAddr) != 6 {
			return nil, fmt.Errorf("%s должен быть включённым Ethernet-интерфейсом", name)
		}
		out = append(out, l)
	}
	return out, nil
}

func (b *Linux) Check(c Config, lan string) error {
	links, err := b.interfaces(c, lan)
	if err != nil {
		return err
	}
	for _, l := range links {
		a := l.Attrs()
		if x := a.Xdp; x != nil && x.Attached {
			own, ok := b.active[a.Name]
			if !ok || !own.matches(l) {
				return fmt.Errorf("на %s уже работает другая программа XDP или захват", a.Name)
			}
		}
	}
	return nil
}

func (a attachment) matches(l netlink.Link) bool {
	attrs := l.Attrs()
	if attrs.Index != a.index || attrs.Xdp == nil || !attrs.Xdp.Attached {
		return false
	}
	info, err := a.Info()
	return err == nil && info.XDP() != nil && int(info.XDP().Ifindex) == attrs.Index && info.Program == a.programID && uint32(a.programID) == attrs.Xdp.ProgId
}

func (b *Linux) Verify(c Config, lan string) error {
	if len(b.active) != len(c.Interfaces) || len(c.Interfaces) > 0 && b.mode != c.Mode {
		return errors.New("профиль XDP не загружен целиком")
	}
	links, err := b.interfaces(c, lan)
	if err != nil {
		return err
	}
	for _, l := range links {
		a, ok := b.active[l.Attrs().Name]
		if !ok || !a.matches(l) {
			return fmt.Errorf("программа XDP на %s изменилась", l.Attrs().Name)
		}
	}
	return nil
}

func (b *Linux) Deactivate() error {
	var err error
	for name, a := range b.active {
		if e := a.Close(); e != nil {
			err = errors.Join(err, e)
		}
		delete(b.active, name)
	}
	if b.counters != nil {
		err = errors.Join(err, b.counters.Close())
		b.counters = nil
	}
	b.mode = ""
	return err
}

type prefixKey struct {
	Bits    uint32
	Family  uint32
	Address [16]byte
}

func newTrie(values []string) (*ebpf.Map, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: 24, ValueSize: 4, MaxEntries: uint32(max(1, len(values))), Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			m.Close()
			return nil, err
		}
		k := prefixKey{Bits: 32 + uint32(p.Bits()), Family: 6, Address: p.Addr().As16()}
		if p.Addr().Is4() {
			k.Family = 4
			k.Address = [16]byte{}
			a := p.Addr().As4()
			copy(k.Address[:], a[:])
		}
		if err = m.Put(k, uint32(1)); err != nil {
			m.Close()
			return nil, err
		}
	}
	return m, nil
}

func (b *Linux) Activate(c Config, lan string) error {
	var err error
	if c, err = c.Normalize(); err != nil {
		return err
	}
	if len(c.Interfaces) == 0 {
		return b.Deactivate()
	}
	links, err := b.interfaces(c, lan)
	if err != nil {
		return err
	}
	if err = b.Check(c, lan); err != nil {
		return err
	}
	manual, err := newTrie(c.Block)
	if err != nil {
		return err
	}
	defer manual.Close()
	var supplied, except []string
	if c.Feed != nil {
		supplied, except = c.Feed.Values, c.Feed.Exceptions
	}
	feedMap, err := newTrie(supplied)
	if err != nil {
		return err
	}
	defer feedMap.Close()
	exceptions, err := newTrie(except)
	if err != nil {
		return err
	}
	defer exceptions.Close()
	counters, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 48, MaxEntries: uint32(len(links))})
	if err != nil {
		return err
	}
	defer func() {
		if b.counters != counters {
			_ = counters.Close()
		}
	}()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	for _, l := range links {
		if err = counters.Put(uint32(l.Attrs().Index), make([]Counters, cpus)); err != nil {
			return err
		}
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "gfw_xdp_guard", Type: ebpf.XDP, AttachType: ebpf.AttachXDP, License: "GPL",
		Instructions: program(c.Match, len(c.Block) > 0, c.Feed != nil, len(except) > 0, manual.FD(), feedMap.FD(), exceptions.FD(), counters.FD())})
	if err != nil {
		return fmt.Errorf("ядро отклонило XDP: %w", err)
	}
	defer program.Close()
	info, err := program.Info()
	if err != nil {
		return err
	}
	programID, ok := info.ID()
	if !ok {
		return errors.New("ядро не вернуло ID программы XDP")
	}
	if err = b.Deactivate(); err != nil {
		return err
	}
	b.active = make(map[string]attachment, len(links))
	b.counters = counters
	b.mode = c.Mode
	mode := link.XDPDriverMode
	if c.Mode == "generic" {
		mode = link.XDPGenericMode
	}
	for _, l := range links {
		a := l.Attrs()
		attached, err := link.AttachXDP(link.XDPOptions{Program: program, Interface: a.Index, Flags: mode})
		if err != nil {
			return errors.Join(fmt.Errorf("XDP на %s: %w", a.Name, err), b.Deactivate())
		}
		b.active[a.Name] = attachment{Link: attached, index: a.Index, programID: programID}
	}
	if err = b.Verify(c, lan); err != nil {
		return errors.Join(err, b.Deactivate())
	}
	return nil
}

func (b *Linux) Ports() ([]Port, error) {
	out := make([]Port, 0, len(b.active))
	for name, a := range b.active {
		var entries []Counters
		if err := b.counters.Lookup(uint32(a.index), &entries); err != nil {
			return nil, err
		}
		p := Port{Name: name, IfIndex: a.index}
		for _, v := range entries {
			p.Passed += v.Passed
			p.PassedBytes += v.PassedBytes
			p.ManualDrops += v.ManualDrops
			p.ManualBytes += v.ManualBytes
			p.FeedDrops += v.FeedDrops
			p.FeedBytes += v.FeedBytes
		}
		out = append(out, p)
	}
	return out, nil
}
