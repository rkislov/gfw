package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	netplanFile = "/etc/netplan/90-gfw.yaml"
	networkdDir = "/run/systemd/network"
)

var netplanDirs = []string{"/lib/netplan", "/etc/netplan", "/run/netplan"}

type Netplan struct{ Linux }

type NetplanSnapshot struct {
	Before      Config          `json:"before"`
	After       Config          `json:"after"`
	YAML        *File           `json:"yaml,omitempty"`
	BeforeUnits map[string]File `json:"before_units"`
	AfterUnits  map[string]File `json:"after_units"`
	LAN         []string        `json:"lan_addresses"`
}

func (Netplan) BackendName() string { return "netplan" }

func networkdProfile(ctx context.Context, name string) (string, error) {
	raw, err := command(ctx, "/usr/bin/networkctl", "--json=short", "--no-pager", "status", name)
	if err != nil {
		return "", err
	}
	var status struct {
		NetworkFile string
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		return "", fmt.Errorf("состояние networkd для %s: %w", name, err)
	}
	return status.NetworkFile, nil
}

func (n Netplan) Prepare(c, old Config) (Snapshot, Plan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return n.prepare(ctx, Canonical(c), old)
}

func (n Netplan) prepare(ctx context.Context, c, old Config) (Snapshot, Plan, error) {
	n.ctx = ctx
	s := newSnapshot(c, old)
	if err := Validate(c); err != nil {
		return s, Plan{}, err
	}
	if err := n.prepareRuntime(c, old, &s); err != nil {
		return s, Plan{}, err
	}
	for _, name := range s.Scope {
		if slices.Contains(s.Protected, name) {
			return s, Plan{}, fmt.Errorf("%s: LAN и его зависимости настраиваются в исходном профиле Netplan", name)
		}
	}
	target := c.Map()
	for _, l := range c.Interfaces {
		if l.Type == "vlan" {
			if _, ok := target[l.Parent]; !ok {
				return s, Plan{}, fmt.Errorf("%s: родитель VLAN должен управляться GFW", l.Name)
			}
		}
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "systemd-networkd.service"); err != nil {
		return s, Plan{}, errors.New("для управления Netplan нужна запущенная служба systemd-networkd")
	}
	if _, err := command(ctx, "/usr/bin/busctl", "--system", "--timeout=4s", "status", "org.freedesktop.network1"); err != nil {
		return s, Plan{}, errors.New("systemd-networkd недоступен через системную D-Bus")
	}
	if err := rejectManagers([]string{"NetworkManager"}); err != nil {
		return s, Plan{}, err
	}
	yamlOld, err := renderNetplan(old)
	if err != nil {
		return s, Plan{}, err
	}
	yamlNew, err := renderNetplan(c)
	if err != nil {
		return s, Plan{}, err
	}
	onDisk, err := configFile(netplanFile)
	if err != nil {
		return s, Plan{}, err
	}
	if onDisk != nil && !sameFile(onDisk, yamlOld) {
		return s, Plan{}, errors.New("файл Netplan GFW изменён вне панели")
	}
	base, err := netplanInputs()
	if err != nil {
		return s, Plan{}, err
	}
	generated, err := generate(ctx, base, nil)
	if err != nil {
		return s, Plan{}, err
	}
	before := map[string]File{}
	if yamlOld != nil {
		combined, err := generate(ctx, base, yamlOld)
		if err != nil {
			return s, Plan{}, err
		}
		before, err = ownedUnits(generated, combined, old)
		if err != nil {
			return s, Plan{}, err
		}
	}
	combined, err := generate(ctx, base, yamlNew)
	if err != nil {
		return s, Plan{}, err
	}
	after, err := ownedUnits(generated, combined, c)
	if err != nil {
		return s, Plan{}, err
	}
	for _, l := range s.Links {
		name := l.Link.Name
		profile, err := networkdProfile(ctx, name)
		if err != nil {
			return s, Plan{}, err
		}
		managed := "10-netplan-" + name + ".network"
		if profile != "" && (before[managed].Body == "" || profile != filepath.Join(networkdDir, managed)) {
			return s, Plan{}, fmt.Errorf("%s: интерфейс использует внешний профиль %s", name, profile)
		}
	}
	if err := checkUnits(before, after, false); err != nil {
		return s, Plan{}, err
	}
	live, _, err := n.live()
	if err != nil {
		return s, Plan{}, err
	}
	s.Netplan = &NetplanSnapshot{old, c, onDisk, before, after, live[n.LAN].Link.Addresses}
	files := map[string]map[string]string{}
	actions := []string{"Удалить " + netplanFile}
	if yamlNew != nil {
		files["/etc/netplan"] = map[string]string{"90-gfw.yaml": yamlNew.Body}
		actions = []string{"Сохранить " + netplanFile}
	}
	for _, name := range s.Scope {
		if _, keep := target[name]; keep {
			actions = append(actions, "Настроить "+name)
		} else {
			actions = append(actions, "Удалить виртуальный интерфейс "+name)
		}
	}
	return s, Plan{Backend: "netplan", Files: files, Actions: actions, Protected: s.Protected, CanApply: true,
		Warnings: []string{"LAN и его зависимости остаются в исходной конфигурации Ubuntu.", "Netplan проверил YAML в изолированном каталоге. Изменения вступают в силу через systemd-networkd и требуют подтверждения."}}, nil
}

func checkUnits(before, after map[string]File, recovery bool) error {
	names := maps.Clone(before)
	maps.Copy(names, after)
	for name := range names {
		if filepath.Base(name) != name || !strings.HasPrefix(name, "10-netplan-") {
			return fmt.Errorf("недопустимое имя профиля %q", name)
		}
		f, err := configFile(filepath.Join(networkdDir, name))
		if err != nil {
			return err
		}
		if f != nil && f.Body != before[name].Body && (!recovery || f.Body != after[name].Body) {
			return fmt.Errorf("изменён внешний профиль networkd %s", name)
		}
	}
	return nil
}

func replaceFile(path string, file *File) error {
	if file != nil {
		return atomicFile(path, *file)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceUnits(before, after map[string]File) error {
	if err := os.Mkdir(networkdDir, 0755); err == nil {
		if err := os.Chmod(networkdDir, 0755); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := validateRoot(networkdDir); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(after)) {
		file := after[name]
		path := filepath.Join(networkdDir, name)
		current, err := configFile(path)
		if err != nil {
			return err
		}
		if !sameFile(current, &file) {
			if err := atomicFile(path, file); err != nil {
				return err
			}
		}
	}
	for name := range before {
		if _, keep := after[name]; !keep {
			if err := replaceFile(filepath.Join(networkdDir, name), nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n Netplan) removeVirtual(previous, next map[string]File, c Config, protectedNames []string) error {
	live, _, err := n.live()
	if err != nil {
		return err
	}
	ordered, err := Order(c.Interfaces)
	if err != nil {
		return err
	}
	slices.Reverse(ordered)
	for _, l := range ordered {
		file := "10-netplan-" + l.Name + ".netdev"
		if previous[file] == next[file] || previous[file].Body == "" {
			continue
		}
		if actual, exists := live[l.Name]; exists {
			if slices.Contains(protectedNames, l.Name) || l.Type == "physical" || actual.Link.Type != l.Type {
				return fmt.Errorf("небезопасно удалять интерфейс %s", l.Name)
			}
			if err := n.cmd("link", "delete", "dev", l.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n Netplan) Activate(c, old Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	n.ctx = ctx
	c = Canonical(c)
	s, _, err := n.prepare(ctx, c, old)
	if err != nil {
		return err
	}
	p := s.Netplan
	y, err := renderNetplan(c)
	if err != nil {
		return err
	}
	if err = replaceFile(netplanFile, y); err != nil {
		return err
	}
	if err = replaceUnits(p.BeforeUnits, p.AfterUnits); err != nil {
		return err
	}
	if err = n.removeVirtual(p.BeforeUnits, p.AfterUnits, old, s.Protected); err != nil {
		return err
	}
	if _, err = command(ctx, "/usr/bin/networkctl", "reload"); err != nil {
		return err
	}
	if maps.Equal(p.BeforeUnits, p.AfterUnits) && len(c.Interfaces) > 0 {
		// A reload leaves unchanged profiles alone. Reconfigure managed links
		// when recovering a confirmed revision whose runtime has drifted.
		if err := n.reconfigure(ctx, c); err != nil {
			return err
		}
	}
	if err := n.waitNetwork(ctx, c, p.LAN); err != nil {
		return err
	}
	return n.checkRemoved(old, c)
}

func (n Netplan) reconfigure(ctx context.Context, c Config) error {
	live, _, err := n.live()
	if err != nil {
		return err
	}
	args := []string{"reconfigure"}
	for _, link := range c.Interfaces {
		if _, exists := live[link.Name]; exists {
			args = append(args, link.Name)
		}
	}
	if len(args) == 1 {
		return nil
	}
	_, err = command(ctx, "/usr/bin/networkctl", args...)
	return err
}

func (n Netplan) Restore(s Snapshot) error {
	p := s.Netplan
	if p == nil {
		return errors.New("журнал сети не содержит снимок Netplan")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	n.ctx = ctx
	if err := checkUnits(p.BeforeUnits, p.AfterUnits, true); err != nil {
		return err
	}
	current, err := configFile(netplanFile)
	if err != nil {
		return err
	}
	target, err := renderNetplan(p.After)
	if err != nil {
		return err
	}
	if !sameFile(current, p.YAML) && !sameFile(current, target) {
		return errors.New("файл Netplan GFW изменён во время операции")
	}
	if err := replaceFile(netplanFile, p.YAML); err != nil {
		return err
	}
	if err := replaceUnits(p.AfterUnits, p.BeforeUnits); err != nil {
		return err
	}
	if err := n.removeVirtual(p.AfterUnits, p.BeforeUnits, p.After, s.Protected); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/networkctl", "reload"); err != nil {
		return err
	}
	// A newly adopted physical link has no networkd profile after rollback.
	// Restore its original MTU, flags, addresses and routes from the kernel snapshot.
	before := p.Before.Map()
	names := []string{}
	links := []RuntimeLink{}
	routes := []RuntimeRoute{}
	for _, l := range s.Links {
		if _, owned := before[l.Link.Name]; !owned {
			profile, err := networkdProfile(ctx, l.Link.Name)
			if err != nil {
				return err
			}
			if profile != "" {
				return fmt.Errorf("%s: восстановлению мешает профиль %s", l.Link.Name, profile)
			}
			names = append(names, l.Link.Name)
			links = append(links, l)
		}
	}
	if len(names) > 0 {
		for _, r := range s.Routes {
			if slices.Contains(names, r.Route.Interface) {
				routes = append(routes, r)
			}
		}
		if err := n.reconcile(names, links, routes, s.Protected); err != nil {
			return err
		}
	}
	if err := n.waitNetwork(ctx, p.Before, p.LAN); err != nil {
		return err
	}
	return n.checkRemoved(p.After, p.Before)
}

func (n Netplan) checkRemoved(before, after Config) error {
	live, _, err := n.live()
	if err != nil {
		return err
	}
	target := after.Map()
	for _, link := range before.Interfaces {
		if _, retained := target[link.Name]; link.Type != "physical" && !retained {
			if _, exists := live[link.Name]; exists {
				return fmt.Errorf("сетевой интерфейс %s не удалён", link.Name)
			}
		}
	}
	return nil
}

func (n Netplan) Verify(c Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	n.ctx = ctx
	expected, err := renderNetplan(c)
	if err != nil {
		return err
	}
	f, err := configFile(netplanFile)
	if err != nil {
		return err
	}
	if !sameFile(f, expected) {
		return errors.New("сохранённый профиль Netplan отличается от подтверждённого")
	}
	return n.waitNetwork(ctx, c, nil)
}

func (n Netplan) waitNetwork(ctx context.Context, c Config, addresses []string) error {
	var last error
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		last = n.verifyNetwork(ctx, c, addresses)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return last
		case <-ticker.C:
		}
	}
}

func (n Netplan) verifyNetwork(ctx context.Context, c Config, addresses []string) error {
	waiting, err := n.verifyRuntime(c)
	if err != nil {
		return err
	}
	if waiting {
		return errors.New("проверка адреса IPv6 ещё не завершена")
	}
	for _, l := range c.Interfaces {
		actual, err := networkdProfile(ctx, l.Name)
		if err != nil {
			return err
		}
		if actual != filepath.Join(networkdDir, "10-netplan-"+l.Name+".network") {
			return fmt.Errorf("%s: networkd не загрузил профиль GFW", l.Name)
		}
	}
	live, _, err := n.live()
	if err != nil {
		return err
	}
	if _, err = protected(live, n.LAN); err != nil {
		return err
	}
	for _, a := range addresses {
		if !slices.Contains(live[n.LAN].Link.Addresses, a) {
			return fmt.Errorf("LAN %s потерял адрес %s", n.LAN, a)
		}
	}
	return nil
}

var _ Backend = Netplan{}
