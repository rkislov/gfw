package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type diskJournal struct {
	path string
	lock *os.File
}

func openJournal(dir string) (*diskJournal, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	owner, owned := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !owned || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("agent state directory must be private (0700), not a symlink")
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another agent owns the state directory")
	}
	return &diskJournal{path: filepath.Join(dir, "journal.json"), lock: f}, nil
}
func (d *diskJournal) close() error { return d.lock.Close() }
func (d *diskJournal) load() (journal, error) {
	f, err := os.Open(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return journal{Version: 1, History: []Record{}}, nil
	}
	if err != nil {
		return journal{}, err
	}
	defer f.Close()
	raw, err := readLimited(f)
	if err != nil {
		return journal{}, err
	}
	var j journal
	if err = json.Unmarshal(raw, &j); err != nil {
		return j, err
	}
	if j.Version < 1 || j.Version > 14 {
		return j, fmt.Errorf("unsupported journal version %d", j.Version)
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "network") != (j.Pending.Network != nil)) {
		return j, errors.New("inconsistent network recovery journal")
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "services") != (j.Pending.Services != nil)) {
		return j, errors.New("inconsistent services recovery journal")
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "wireguard") != (j.Pending.WireGuard != nil)) {
		return j, errors.New("inconsistent WireGuard recovery journal")
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "openvpn") != (j.Pending.OpenVPN != nil)) {
		return j, errors.New("inconsistent OpenVPN recovery journal")
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "ipsec") != (j.Pending.IPsec != nil)) {
		return j, errors.New("inconsistent IPsec recovery journal")
	}

	if j.Pending != nil && ((j.Pending.Record.Kind == "ids") != (j.Pending.IDS != nil)) {
		return j, errors.New("inconsistent IDS recovery journal")
	}
	if j.Pending != nil && ((j.Pending.Record.Kind == "xdp") != (j.Pending.XDP != nil)) {
		return j, errors.New("inconsistent XDP recovery journal")
	}
	return j, nil
}
func (d *diskJournal) save(j journal) error {
	raw, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > 32<<20 {
		return errors.New("journal exceeds 32 MiB")
	}
	f, err := os.CreateTemp(filepath.Dir(d.path), ".journal-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, d.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(d.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
