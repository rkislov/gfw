package netconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type File struct {
	Body string `json:"body"`
	Mode uint32 `json:"mode"`
}
type Directory struct {
	Exists bool            `json:"exists"`
	Files  map[string]File `json:"files"`
}

var allowedFiles = map[string]bool{"options": true, "ipv4address": true, "ipv6address": true, "ipv4route": true, "ipv6route": true, "sysctl.conf": true, ".gfw-owned": true}

func validateRoot(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("etcnet root must be absolute")
	}
	i, err := os.Lstat(root)
	if err != nil {
		return err
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || int(s.Uid) != os.Geteuid() || i.Mode().Perm()&0022 != 0 {
		return errors.New("etcnet root must be owned by agent and not writable by group/others")
	}
	return nil
}
func readDirectory(root, name string) (Directory, error) {
	d := Directory{Files: map[string]File{}}
	if !Name.MatchString(name) {
		return d, errors.New("invalid interface name")
	}
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
		return d, errors.New("unsafe etcnet interface directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return d, err
	}
	d.Exists = true
	for _, entry := range entries {
		if !allowedFiles[entry.Name()] {
			return d, fmt.Errorf("%s: неподдерживаемый файл etcnet %s; автоматическая передача запрещена", name, entry.Name())
		}
		i, err := entry.Info()
		if err != nil {
			return d, err
		}
		if !i.Mode().IsRegular() || i.Size() > 1<<20 {
			return d, errors.New("etcnet files must be regular and at most 1 MiB")
		}
		b, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return d, err
		}
		d.Files[entry.Name()] = File{string(b), uint32(i.Mode().Perm())}
	}
	return d, nil
}
func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func atomicFile(path string, f File) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gfw-tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(os.FileMode(f.Mode)); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.WriteString(f.Body); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func writeDirectory(root, name string, d Directory) error {
	if !Name.MatchString(name) {
		return errors.New("invalid interface name")
	}
	path := filepath.Join(root, name)
	// Partial multi-file writes after a crash leave only our temporary files.
	// Remove those before the strict directory inventory used during recovery.
	if entries, e := os.ReadDir(path); e == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".gfw-tmp-") && entry.Type().IsRegular() {
				if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
					return err
				}
			}
		}
	}
	current, err := readDirectory(root, name)
	if err != nil {
		return err
	}
	if !d.Exists {
		for n := range current.Files {
			if err = os.Remove(filepath.Join(path, n)); err != nil {
				return err
			}
		}
		if current.Exists {
			if err = os.Remove(path); err != nil {
				return err
			}
		}
		return syncDirectory(root)
	}
	if err = os.MkdirAll(path, 0755); err != nil {
		return err
	}
	names := []string{}
	for n := range d.Files {
		if !allowedFiles[n] {
			return errors.New("unsupported restore filename")
		}
		if n != "options" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if _, ok := d.Files["options"]; ok {
		names = append(names, "options")
	}
	for _, n := range names {
		if err = atomicFile(filepath.Join(path, n), d.Files[n]); err != nil {
			return err
		}
	}
	for n := range current.Files {
		if _, ok := d.Files[n]; !ok {
			if err = os.Remove(filepath.Join(path, n)); err != nil {
				return err
			}
		}
	}
	return syncDirectory(root)
}
func renderDirectories(c Config) map[string]Directory {
	out := map[string]Directory{}
	for n, files := range Render(c) {
		d := Directory{Exists: true, Files: map[string]File{}}
		for name, body := range files {
			d.Files[name] = File{body, 0644}
		}
		out[n] = d
	}
	return out
}
