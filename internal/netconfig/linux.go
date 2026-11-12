package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

func set(names []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}
func scope(c, old Config) []string {
	m := map[string]bool{}
	for _, cfg := range []Config{c, old} {
		for _, a := range cfg.Interfaces {
			m[a.Name] = true
		}
	}
	names := []string{}
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func masters(c Config) map[string]string {
	out := map[string]string{}
	for _, l := range c.Interfaces {
		for _, m := range l.Members {
			out[m] = l.Name
		}
	}
	return out
}
func equalStrings(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\n") == strings.Join(y, "\n")
}
func protected(live map[string]RuntimeLink, lan string) ([]string, error) {
	r, ok := live[lan]
	if !ok || !r.Link.Up || r.Master != "" {
		return nil, errors.New("LAN должен существовать, быть включён и не быть портом другого интерфейса")
	}
	out := map[string]bool{}
	var visit func(string)
	visit = func(n string) {
		if out[n] {
			return
		}
		out[n] = true
		r := live[n]
		if r.Link.Parent != "" {
			visit(r.Link.Parent)
		}
		for _, m := range r.Link.Members {
			visit(m)
		}
	}
	visit(lan)
	names := []string{}
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
func noOtherManager() error {
	return rejectManagers([]string{"NetworkManager", "systemd-network", "dhcpcd", "dhclient", "udhcpc", "ifplugd"})
}

func rejectManagers(managers []string) error {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		b, _ := os.ReadFile("/proc/" + d.Name() + "/comm")
		name := strings.TrimSpace(string(b))
		if slices.Contains(managers, name) {
			return fmt.Errorf("работает %s: сначала освободите интерфейсы для GFW", name)
		}
	}
	return nil
}
func newSnapshot(c, old Config) Snapshot {
	return Snapshot{Scope: scope(c, old), Files: map[string]Directory{}, Links: []RuntimeLink{}, Routes: []RuntimeRoute{}}
}

func (l Linux) Prepare(c, old Config) (Snapshot, Plan, error) {
	c = Canonical(c)
	s := newSnapshot(c, old)
	if err := Validate(c); err != nil {
		return s, Plan{}, err
	}
	if err := validateRoot(l.Root); err != nil {
		return s, Plan{}, err
	}
	if err := noOtherManager(); err != nil {
		return s, Plan{}, err
	}
	entries, err := os.ReadDir(l.Root)
	if err != nil {
		return s, Plan{}, err
	}
	for _, entry := range entries {
		for _, n := range s.Scope {
			if strings.HasPrefix(entry.Name(), n+"@") || strings.HasPrefix(entry.Name(), n+"#") {
				return s, Plan{}, fmt.Errorf("%s: сначала перенесите профиль etcnet %s", n, entry.Name())
			}
		}
	}
	target, previous := c.Map(), old.Map()
	for _, n := range s.Scope {
		files, err := readDirectory(l.Root, n)
		if err != nil {
			return s, Plan{}, err
		}
		s.Files[n] = files
		_, owned := previous[n]
		if _, retained := target[n]; retained && owned && files.Exists && files.Files[".gfw-owned"].Body != "gfw-network-v1\n" {
			return s, Plan{}, fmt.Errorf("%s: файлы etcnet изменены другим владельцем", n)
		}
	}
	if err := l.prepareRuntime(c, old, &s); err != nil {
		return s, Plan{}, err
	}
	actions := []string{}
	for _, n := range s.Scope {
		if _, ok := target[n]; ok {
			actions = append(actions, "Настроить "+n+" и сохранить /etc/net/ifaces/"+n)
		} else {
			actions = append(actions, "Удалить управляемый виртуальный интерфейс "+n)
		}
	}
	return s, Plan{Files: Render(c), Actions: actions, Protected: s.Protected, CanApply: true, Warnings: []string{"LAN и его зависимости не удаляются и не перестраиваются. На LAN сохраняется существующий IP.", "Настраиваются только статические IP и маршруты основной таблицы. Потребуется подтверждение доступа.", "Изменения нескольких интерфейсов не атомарны; при ошибке или отсутствии подтверждения восстанавливаются файлы etcnet и состояние сети."}}, nil
}

func (l Linux) prepareRuntime(c, old Config, s *Snapshot) error {
	live, routes, err := l.live()
	if err != nil {
		return err
	}
	s.Protected, err = protected(live, l.LAN)
	if err != nil {
		return err
	}
	target, previous, affected, protectedSet := c.Map(), old.Map(), set(s.Scope), set(s.Protected)
	wantedMasters := masters(c)
	for _, n := range s.Scope {
		current, exists := live[n]
		if exists {
			s.Links = append(s.Links, current)
			if current.Dynamic || (current.Tentative && current.Link.Up) {
				return fmt.Errorf("%s: динамические/непроверенные адреса пока не поддержаны", n)
			}
		}
		want, retained := target[n]
		before, owned := previous[n]
		if !retained {
			if before.Type == "physical" || protectedSet[n] {
				return fmt.Errorf("нельзя удалить физический или защищённый LAN-интерфейс %s", n)
			}
		} else {
			if !exists && want.Type == "physical" {
				return fmt.Errorf("физический интерфейс %s не найден", n)
			}
			if exists && want.Type != current.Link.Type {
				return fmt.Errorf("%s: смена типа существующего интерфейса запрещена", n)
			}
			if exists && !owned && want.Type != "physical" {
				return fmt.Errorf("%s: импорт существующего виртуального интерфейса пока не поддержан; его параметры нужно перенести отдельно", n)
			}
			if (exists || s.Files[n].Exists) && !owned && !want.Adopt {
				return fmt.Errorf("%s: требуется явная передача под управление GFW", n)
			}
			if want.Type == "vlan" {
				parent, ok := target[want.Parent]
				if !ok {
					if _, deleted := previous[want.Parent]; deleted {
						return errors.New("нельзя удалить родительский интерфейс используемого VLAN")
					}
					r, exists := live[want.Parent]
					if !exists || !r.Link.Up {
						return errors.New("родитель VLAN не найден или выключен")
					}
					parent = r.Link
				}
				if want.MTU > parent.MTU {
					return errors.New("MTU VLAN больше родительского")
				}
			}
			if protectedSet[n] {
				a := current.Link
				if !want.Up || want.MTU != a.MTU || want.Parent != a.Parent || want.VLAN != a.VLAN || want.BondMode != a.BondMode || !equalStrings(want.Members, a.Members) || wantedMasters[n] != current.Master {
					return fmt.Errorf("%s: нельзя менять структуру, MTU или состояние LAN и его зависимостей", n)
				}
				if n == l.LAN {
					preserved := false
					for _, a := range want.Addresses {
						for _, b := range current.Link.Addresses {
							if a == b {
								preserved = true
							}
						}
					}
					if !preserved {
						return errors.New("на LAN нужно сохранить хотя бы один существующий IP/CIDR")
					}
				}
				if n != l.LAN && !equalStrings(want.Addresses, a.Addresses) {
					return errors.New("нельзя менять адреса зависимости LAN")
				}
			}
			if exists && current.Master != "" && !affected[current.Master] {
				return fmt.Errorf("%s входит в неуправляемый %s", n, current.Master)
			}
		}
	}
	// An unmanaged child or slave must never disappear as a side effect of
	// replacing one of our virtual links.
	for n, r := range live {
		if !affected[n] {
			for _, want := range c.Interfaces {
				for _, a := range want.Addresses {
					p, _ := netip.ParsePrefix(a)
					for _, b := range r.Link.Addresses {
						q, _ := netip.ParsePrefix(b)
						if p.Overlaps(q) {
							return fmt.Errorf("подсеть %s пересекается с неуправляемым %s", want.Name, n)
						}
					}
				}
			}
		}
		if !affected[n] && ((affected[r.Link.Parent] && !protectedSet[r.Link.Parent]) || (affected[r.Master] && !protectedSet[r.Master])) {
			return fmt.Errorf("%s имеет внешнюю зависимость %s; включите её в план", r.Link.Parent+r.Master, n)
		}
		if _, ok := target[n]; !ok && protectedSet[n] && affected[n] {
			return errors.New("удаление зависимости LAN запрещено")
		}
	}
	for _, r := range routes {
		if r.Protocol == "unsupported" {
			return errors.New("расширенные маршруты main (multipath/blackhole/nexthop) требуют отдельного управления")
		}
		if affected[r.Route.Interface] {
			if r.Protocol == "dhcp" || r.Protocol == "ra" {
				return errors.New("динамические маршруты на управляемом интерфейсе не поддержаны")
			}
			s.Routes = append(s.Routes, r)
		} else {
			for _, want := range c.Routes {
				if want.Destination == r.Route.Destination && want.Metric == r.Route.Metric {
					return errors.New("маршрут конфликтует с маршрутом неуправляемого интерфейса")
				}
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		raw, err := l.run("-j", family, "route", "show", "table", "all")
		if err != nil {
			return err
		}
		var rows []struct {
			Dev   string `json:"dev"`
			Table any    `json:"table"`
		}
		if err = json.Unmarshal(raw, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			table := textValue(r.Table)
			if affected[r.Dev] && table != "" && table != "main" && table != "254" && table != "local" && table != "255" {
				return errors.New("на интерфейсе есть маршруты дополнительных таблиц; изменение запрещено")
			}
		}
	}
	return nil
}

func family(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	if p.Addr().Is4() {
		return "-4"
	}
	return "-6"
}
func routeArgs(r RuntimeRoute, action string) []string {
	args := []string{family(r.Route.Destination), "route", action, r.Route.Destination}
	if r.Route.Gateway != "" {
		args = append(args, "via", r.Route.Gateway)
	}
	args = append(args, "dev", r.Route.Interface)
	if r.Route.Metric != 0 {
		args = append(args, "metric", strconv.Itoa(r.Route.Metric))
	}
	if r.Protocol != "" {
		args = append(args, "proto", r.Protocol)
	}
	if action != "del" {
		if r.Source != "" {
			args = append(args, "src", r.Source)
		}
		if r.Scope != "" {
			args = append(args, "scope", r.Scope)
		}
		if r.Onlink {
			args = append(args, "onlink")
		}
	}
	return args
}
func (l Linux) addresses(name string, want []string) error {
	live, _, err := l.live()
	if err != nil {
		return err
	}
	current, exists := live[name]
	if !exists {
		return errors.New("interface disappeared")
	}
	old := set(current.Link.Addresses)
	next := set(want)
	// Make-before-break is particularly important for secondary LAN addresses.
	for _, a := range want {
		if !old[a] {
			if err = l.cmd(family(a), "addr", "add", a, "dev", name); err != nil {
				return err
			}
		}
	}
	for _, a := range current.Link.Addresses {
		if !next[a] {
			if err = l.cmd(family(a), "addr", "del", a, "dev", name); err != nil {
				return err
			}
		}
	}
	return nil
}
func (l Linux) reconcile(names []string, target []RuntimeLink, routes []RuntimeRoute, protect []string) error {
	live, currentRoutes, err := l.live()
	if err != nil {
		return err
	}
	affected, protectedSet := set(names), set(protect)
	for _, r := range currentRoutes {
		if affected[r.Route.Interface] {
			if err = l.cmd(routeArgs(r, "del")...); err != nil {
				return err
			}
		}
	}
	// Detach only explicitly owned ports. Their masters and children have already
	// been checked by Prepare before any mutation and captured durably.
	for _, n := range names {
		if r, ok := live[n]; ok && r.Master != "" && !protectedSet[n] {
			if err = l.cmd("link", "set", "dev", n, "nomaster"); err != nil {
				return err
			}
		}
	}
	current := []Link{}
	for _, n := range names {
		if r, ok := live[n]; ok {
			current = append(current, r.Link)
		}
	}
	ordered, err := Order(current)
	if err != nil {
		return err
	}
	for i := len(ordered) - 1; i >= 0; i-- {
		r := ordered[i]
		if r.Type != "physical" && !protectedSet[r.Name] {
			if err = l.cmd("link", "del", "dev", r.Name); err != nil {
				return err
			}
		}
	}
	desired := []Link{}
	index := map[string]RuntimeLink{}
	for _, r := range target {
		desired = append(desired, r.Link)
		index[r.Link.Name] = r
	}
	ordered, err = Order(desired)
	if err != nil {
		return err
	}
	for _, r := range ordered {
		if r.Type != "physical" && !protectedSet[r.Name] {
			args := []string{"link", "add", "name", r.Name, "type", r.Type}
			switch r.Type {
			case "vlan":
				args = []string{"link", "add", "link", r.Parent, "name", r.Name, "type", "vlan", "id", strconv.Itoa(r.VLAN)}
			case "bridge":
				args = append(args, "stp_state", "0")
			case "bond":
				args = append(args, "mode", r.BondMode, "miimon", "100")
			}
			if err = l.cmd(args...); err != nil {
				return err
			}
		}
		if !protectedSet[r.Name] {
			if err = l.cmd("link", "set", "dev", r.Name, "mtu", strconv.Itoa(r.MTU)); err != nil {
				return err
			}
			if mac := index[r.Name].MAC; mac != "" {
				if err = l.cmd("link", "set", "dev", r.Name, "down"); err != nil {
					return err
				}
				if err = l.cmd("link", "set", "dev", r.Name, "address", mac); err != nil {
					return err
				}
			}
		}
		for _, n := range r.Members {
			if protectedSet[n] {
				continue
			}
			if r.Type == "bond" {
				if err = l.cmd("link", "set", "dev", n, "down"); err != nil {
					return err
				}
			}
			if err = l.cmd("link", "set", "dev", n, "master", r.Name); err != nil {
				return err
			}
		}
	}
	// Set addresses only after ports have joined their masters, then bring up
	// ports/masters in dependency order. No global network service restart.
	for _, r := range ordered {
		for key, value := range index[r.Name].IPv6Sysctls {
			if key != "accept_ra" && key != "autoconf" {
				return errors.New("invalid IPv6 sysctl")
			}
			path := "/proc/sys/net/ipv6/conf/" + r.Name + "/" + key
			if err = os.WriteFile(path, []byte(value), 0644); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err = l.addresses(r.Name, r.Addresses); err != nil {
			return err
		}
		state := "down"
		if r.Up {
			state = "up"
		}
		if err = l.cmd("link", "set", "dev", r.Name, state); err != nil {
			return err
		}
	}
	for _, r := range routes {
		if err = l.cmd(routeArgs(r, "add")...); err != nil {
			return err
		}
	}
	return nil
}
func (l Linux) Activate(c, old Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	l.ctx = ctx
	c = Canonical(c)
	// Prepare is intentionally repeated immediately before file writes. A changed
	// external owner or dependency fails and lets the manager restore its snapshot.
	before, _, err := l.Prepare(c, old)
	if err != nil {
		return err
	}
	directories := renderDirectories(c)
	for _, n := range before.Scope {
		d := directories[n]
		if d.Files == nil {
			d.Files = map[string]File{}
		}
		if err = writeDirectory(l.Root, n, d); err != nil {
			return err
		}
	}
	target := []RuntimeLink{}
	for _, r := range c.Interfaces {
		target = append(target, RuntimeLink{Link: r, IPv6Sysctls: map[string]string{"accept_ra": "0", "autoconf": "0"}})
	}
	routes := []RuntimeRoute{}
	for _, r := range c.Routes {
		routes = append(routes, RuntimeRoute{Route: r, Protocol: "186"})
	}
	if err = l.reconcile(before.Scope, target, routes, before.Protected); err != nil {
		return err
	}
	return l.Verify(c)
}
func (l Linux) Restore(s Snapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	l.ctx = ctx
	if err := validateRoot(l.Root); err != nil {
		return err
	}
	var errs []error
	for _, n := range s.Scope {
		if err := writeDirectory(l.Root, n, s.Files[n]); err != nil {
			errs = append(errs, err)
		}
	}
	// Still restore runtime connectivity if a persistent filesystem is failing.
	if err := l.reconcile(s.Scope, s.Links, s.Routes, s.Protected); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		if err := l.verifyRestored(s); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l Linux) verifyRestored(s Snapshot) error {
	live, routes, err := l.live()
	if err != nil {
		return err
	}
	expected := map[string]RuntimeLink{}
	for _, r := range s.Links {
		expected[r.Link.Name] = r
	}
	for _, n := range s.Scope {
		want, existed := expected[n]
		actual, exists := live[n]
		if existed != exists {
			return fmt.Errorf("не восстановлено наличие интерфейса %s", n)
		}
		if existed && (actual.Link.Type != want.Link.Type || actual.Link.Up != want.Link.Up || actual.Link.MTU != want.Link.MTU || actual.Link.Parent != want.Link.Parent || actual.Link.VLAN != want.Link.VLAN || actual.Link.BondMode != want.Link.BondMode || actual.Master != want.Master || !equalStrings(actual.Link.Addresses, want.Link.Addresses) || !equalStrings(actual.Link.Members, want.Link.Members) || actual.MAC != want.MAC) {
			return fmt.Errorf("не восстановлена конфигурация %s", n)
		}
		for key, v := range want.IPv6Sysctls {
			if actual.IPv6Sysctls[key] != v {
				return fmt.Errorf("не восстановлен IPv6 sysctl %s/%s", n, key)
			}
		}
		files, err := readDirectory(l.Root, n)
		if err != nil {
			return err
		}
		before := s.Files[n]
		if files.Exists != before.Exists || len(files.Files) != len(before.Files) {
			return fmt.Errorf("не восстановлены файлы %s", n)
		}
		for name, f := range before.Files {
			if files.Files[name] != f {
				return fmt.Errorf("не восстановлен файл %s/%s", n, name)
			}
		}
	}
	for _, r := range s.Routes {
		found := false
		for _, a := range routes {
			if r.Route == a.Route && r.Protocol == a.Protocol {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("не восстановлен маршрут %s", r.Route.Destination)
		}
	}
	return nil
}
func (l Linux) Verify(c Config) error {
	c = Canonical(c)
	deadline := time.Now().Add(4 * time.Second)
	for {
		waiting, err := l.verifyRuntime(c)
		if err != nil {
			return err
		}
		files := renderDirectories(c)
		for n, want := range files {
			actual, err := readDirectory(l.Root, n)
			if err != nil {
				return err
			}
			for name, f := range want.Files {
				if actual.Files[name].Body != f.Body {
					return fmt.Errorf("файл etcnet %s/%s изменён", n, name)
				}
			}
		}
		if !waiting {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("IPv6 DAD не завершён или обнаружен дубликат")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (l Linux) verifyRuntime(c Config) (bool, error) {
	live, routes, err := l.live()
	if err != nil {
		return false, err
	}
	waiting := false
	wantedMasters := masters(c)
	for _, want := range c.Interfaces {
		r, ok := live[want.Name]
		if !ok || r.Link.Type != want.Type || r.Link.Up != want.Up || r.Link.MTU != want.MTU || r.Link.Parent != want.Parent || r.Link.VLAN != want.VLAN || r.Link.BondMode != want.BondMode || r.Master != wantedMasters[want.Name] || !equalStrings(r.Link.Members, want.Members) || !equalStrings(r.Link.Addresses, want.Addresses) {
			return false, fmt.Errorf("проверка конфигурации %s не пройдена", want.Name)
		}
		waiting = waiting || (r.Tentative && want.Up)
	}
	for _, want := range c.Routes {
		found := false
		for _, r := range routes {
			if r.Route == want {
				found = true
			}
		}
		if !found {
			return false, fmt.Errorf("маршрут %s не установлен", want.Destination)
		}
	}
	wantedLinks := c.Map()
	for _, r := range routes {
		if _, managed := wantedLinks[r.Route.Interface]; managed {
			found := false
			for _, want := range c.Routes {
				if r.Route == want {
					found = true
				}
			}
			if !found {
				return false, fmt.Errorf("обнаружен незапланированный маршрут на %s", r.Route.Interface)
			}
		}
	}
	return waiting, nil
}
