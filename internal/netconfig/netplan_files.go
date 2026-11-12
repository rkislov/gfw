package netconfig

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

func renderNetplan(c Config) (*File, error) {
	if len(c.Interfaces) == 0 {
		return nil, nil
	}
	network := map[string]any{"version": 2}
	groups := map[string]map[string]any{}
	routes := map[string][]map[string]any{}
	for _, r := range c.Routes {
		v := map[string]any{"to": r.Destination, "metric": r.Metric}
		if r.Gateway != "" {
			v["via"] = r.Gateway
		} else {
			v["scope"] = "link"
		}
		routes[r.Interface] = append(routes[r.Interface], v)
	}
	for _, l := range c.Interfaces {
		group := map[string]string{"physical": "ethernets", "vlan": "vlans", "bridge": "bridges", "bond": "bonds"}[l.Type]
		if groups[group] == nil {
			groups[group] = map[string]any{}
			network[group] = groups[group]
		}
		cfg := map[string]any{"renderer": "networkd", "mtu": l.MTU, "dhcp4": false, "dhcp6": false, "accept-ra": false, "optional": true, "ignore-carrier": true}
		if !l.Up {
			cfg["activation-mode"] = "off"
		}
		if len(l.Addresses) > 0 {
			cfg["addresses"] = l.Addresses
		}
		if len(routes[l.Name]) > 0 {
			cfg["routes"] = routes[l.Name]
		}
		switch l.Type {
		case "vlan":
			cfg["id"], cfg["link"] = l.VLAN, l.Parent
		case "bond":
			cfg["interfaces"] = l.Members
			cfg["parameters"] = map[string]any{"mode": l.BondMode, "mii-monitor-interval": "100ms"}
		case "bridge":
			cfg["interfaces"] = l.Members
			cfg["parameters"] = map[string]any{"stp": false, "forward-delay": 0}
		}
		groups[group][l.Name] = cfg
	}
	raw, err := yaml.Marshal(map[string]any{"network": network})
	if err != nil {
		return nil, err
	}
	return &File{Body: "# Managed by GFW\n" + string(raw), Mode: 0600}, nil
}

func command(ctx context.Context, path string, args ...string) ([]byte, error) {
	var stdout, stderr output
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(path), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func configFile(path string) (*File, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("небезопасный файл сети %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &File{string(b), uint32(info.Mode().Perm())}, nil
}

func sameFile(a, b *File) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func generate(ctx context.Context, base map[string]File, file *File) (map[string]File, error) {
	dir, err := os.MkdirTemp("", "netplan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	input := maps.Clone(base)
	if file != nil {
		input[netplanFile] = *file
	}
	for path, f := range input {
		target := filepath.Join(dir, path)
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return nil, err
		}
		if err = os.WriteFile(target, []byte(f.Body), 0600); err != nil {
			return nil, err
		}
	}
	// Run the two Netplan 1.2 stages used by generate --root-dir.
	// The CLI wrapper additionally reloads the host udev daemon.
	args := []string{"--root-dir", dir}
	for _, suffix := range []string{"generator", "generator.early", "generator.late"} {
		path := filepath.Join(dir, "run/systemd", suffix)
		if err = os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
		args = append(args, path)
	}
	if _, err = command(ctx, "/usr/lib/systemd/system-generators/netplan", args...); err != nil {
		return nil, err
	}
	if _, err = command(ctx, "/usr/libexec/netplan/configure", "--root-dir", dir); err != nil {
		return nil, err
	}
	result := map[string]File{}
	entries, err := os.ReadDir(filepath.Join(dir, networkdDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("неподдерживаемый файл Netplan %s", e.Name())
		}
		f, err := configFile(filepath.Join(dir, networkdDir, e.Name()))
		if err != nil {
			return nil, err
		}
		result[e.Name()] = *f
	}
	return result, nil
}

func netplanInputs() (map[string]File, error) {
	base := map[string]File{}
	for _, dir := range netplanDirs {
		if err := validateRoot(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) && dir != filepath.Dir(netplanFile) {
				continue
			}
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".yaml" {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if path == netplanFile {
				continue
			}
			if entry.Name() == filepath.Base(netplanFile) {
				return nil, fmt.Errorf("конфликт имени Netplan: %s", path)
			}
			f, err := configFile(path)
			if err != nil {
				return nil, err
			}
			if f != nil {
				base[path] = *f
			}
		}
	}
	return base, nil
}

func expectedUnits(c Config) map[string]bool {
	names := map[string]bool{}
	for _, l := range c.Interfaces {
		base := "10-netplan-" + l.Name
		names[base+".network"] = true
		if l.Type == "physical" {
			names[base+".link"] = true
		} else {
			names[base+".netdev"] = true
		}
	}
	return names
}

func ownedUnits(base, combined map[string]File, c Config) (map[string]File, error) {
	for name, file := range base {
		if combined[name] != file {
			return nil, fmt.Errorf("Netplan меняет внешний профиль %s", name)
		}
	}
	out := map[string]File{}
	names := expectedUnits(c)
	for name := range names {
		file, exists := combined[name]
		if _, conflict := base[name]; conflict || !exists {
			return nil, fmt.Errorf("профиль %s уже управляется системой или не создан Netplan", name)
		}
		// Only the typed GFW configuration is published here. networkd runs
		// as a separate user, and the agent's primary group is gfw.
		file.Mode = 0644
		out[name] = file
	}
	if len(combined) != len(base)+len(out) {
		return nil, errors.New("Netplan создал файлы вне управляемых интерфейсов GFW")
	}
	return out, nil
}
