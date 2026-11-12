package tuning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const config = "/etc/sysctl.d/80-gfw-performance.conf"
const header = "# GFW performance v1 "
const lockPath = "/var/lib/gfw-agent/sysctl.lock"

type system struct{ proc, config, lock string }

func Execute(action, token string) (Plan, error) {
	return (system{"/proc", config, lockPath}).execute(action, token)
}

func (s system) read(key string) (uint64, error) {
	raw, err := os.ReadFile(s.path(key))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
}

func (s system) path(key string) string {
	return filepath.Join(s.proc, "sys", strings.ReplaceAll(key, ".", "/"))
}

func (s system) baseline() ([]Setting, error) {
	raw, err := os.ReadFile(s.config)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	var settings []Setting
	if !strings.HasPrefix(line, header) || json.Unmarshal([]byte(strings.TrimPrefix(line, header)), &settings) != nil ||
		len(settings) == 0 || !bytes.Equal(raw, configBytes(settings)) {
		return nil, errors.New("файл sysctl GFW изменён вручную или повреждён")
	}
	seen := map[string]bool{}
	for _, v := range settings {
		if seen[v.Key] || !slices.Contains(keys, v.Key) || v.Current >= v.Target || v.Target > 1048576 {
			return nil, errors.New("некорректный журнал sysctl GFW")
		}
		seen[v.Key] = true
	}
	return settings, nil
}

func (s system) plan(baseline []Setting) (Plan, error) {
	raw, err := os.ReadFile(filepath.Join(s.proc, "meminfo"))
	p := Plan{CPUs: runtime.NumCPU(), Settings: []Setting{}, Skipped: []string{}, Managed: len(baseline) != 0}
	if err != nil {
		return p, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			var kib uint64
			if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &kib); err == nil {
				p.MemoryMiB = kib / 1024
			}
			break
		}
	}
	if p.MemoryMiB == 0 {
		return p, errors.New("не удалось определить объём памяти")
	}
	targets := recommendation(p.MemoryMiB, p.CPUs)
	for i, key := range keys {
		current, err := s.read(key)
		if errors.Is(err, os.ErrNotExist) {
			p.Skipped = append(p.Skipped, key)
			continue
		}
		if err != nil {
			return p, err
		}
		target := max(current, targets[i])
		if p.Managed {
			target = current
			for _, old := range baseline {
				if old.Key == key {
					target = old.Target
				}
			}
		}
		p.Settings = append(p.Settings, Setting{key, current, target})
	}
	p.Token = sign(p)
	return p, nil
}

func configBytes(settings []Setting) []byte {
	metadata, _ := json.Marshal(settings)
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s%s\n", header, metadata)
	for _, v := range settings {
		fmt.Fprintf(&b, "%s = %d\n", v.Key, v.Target)
	}
	return b.Bytes()
}

func (s system) writeConfig(settings []Setting) error {
	f, err := os.CreateTemp(filepath.Dir(s.config), ".gfw-performance-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(configBytes(settings))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), s.config)
}

func (s system) write(v Setting) error {
	if err := os.WriteFile(s.path(v.Key), []byte(fmt.Sprintf("%d\n", v.Target)), 0); err != nil {
		return fmt.Errorf("%s: %w", v.Key, err)
	}
	current, err := s.read(v.Key)
	if err == nil && current != v.Target {
		err = fmt.Errorf("%s: ядро вернуло %d вместо %d", v.Key, current, v.Target)
	}
	return err
}

func (s system) restore(settings []Setting) error {
	for _, v := range settings {
		n, err := s.read(v.Key)
		if err != nil {
			return err
		}
		if n != v.Current && n != v.Target {
			return fmt.Errorf("%s изменён вне GFW; проверьте текущее значение и файл %s", v.Key, s.config)
		}
		if v.Key == "net.netfilter.nf_conntrack_max" && n != v.Current {
			count, err := s.read("net.netfilter.nf_conntrack_count")
			if err != nil {
				return err
			}
			if count >= v.Current {
				return fmt.Errorf("conntrack содержит %d записей; для восстановления исходного лимита %d дождитесь снижения нагрузки", count, v.Current)
			}
		}
	}
	var errs error
	for _, v := range settings {
		v.Current, v.Target = v.Target, v.Current
		current, err := s.read(v.Key)
		if err == nil && current != v.Target {
			err = s.write(v)
		}
		errs = errors.Join(errs, err)
	}
	if errs != nil {
		return errs
	}
	return os.Remove(s.config)
}

func (s system) execute(action, token string) (Plan, error) {
	f, err := os.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Plan{}, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return Plan{}, fmt.Errorf("операция sysctl уже выполняется: %w", err)
	}
	before, err := s.baseline()
	if err != nil {
		return Plan{}, err
	}
	p, err := s.plan(before)
	if err != nil {
		return Plan{}, err
	}
	switch action {
	case "plan":
		return p, nil
	case "restore":
		if !p.Managed {
			return p, nil
		}
		if err := s.restore(before); err != nil {
			return Plan{}, err
		}
	case "apply":
		if p.Managed || token == "" || token != p.Token {
			return Plan{}, errors.New("состояние sysctl изменилось или профиль уже активен; обновите предпросмотр")
		}
		for _, v := range p.Settings {
			if v.Target > v.Current {
				before = append(before, v)
			}
		}
		if len(before) == 0 {
			return p, nil
		}
		if err := s.writeConfig(before); err != nil {
			return Plan{}, err
		}
		for _, v := range before {
			if err := s.write(v); err != nil {
				return Plan{}, errors.Join(err, s.restore(before))
			}
		}
	default:
		return Plan{}, errors.New("допустимые действия: plan, apply, restore")
	}
	settings, err := s.baseline()
	if err != nil {
		return Plan{}, err
	}
	return s.plan(settings)
}
