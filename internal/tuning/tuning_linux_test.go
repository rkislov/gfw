package tuning

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPlanApplyRestore(t *testing.T) {
	dir := t.TempDir()
	s := system{dir, filepath.Join(dir, "80-gfw-performance.conf"), filepath.Join(dir, "lock")}
	put := func(path, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(dir, "meminfo"), "MemTotal: 1048576 kB\n")
	put(s.path(keys[0]), "128\n")
	put(s.path(keys[2]), "4096\n")
	put(s.path("net.netfilter.nf_conntrack_count"), "5\n")
	p, err := s.execute("plan", "")
	if err != nil || p.MemoryMiB != 1024 || len(p.Skipped) != 1 || p.Skipped[0] != keys[1] || p.Settings[1].Target != 32768 {
		t.Fatalf("plan: %+v, %v", p, err)
	}
	put(s.path(keys[0]), "129\n")
	if _, err := s.execute("apply", p.Token); err == nil {
		t.Fatal("accepted stale plan")
	}
	p, err = s.execute("plan", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.execute("apply", p.Token)
	if err != nil || !p.Managed || p.Settings[1].Current != 32768 {
		t.Fatalf("apply: %+v, %v", p, err)
	}
	put(s.path("net.netfilter.nf_conntrack_count"), "5000\n")
	if _, err := s.execute("restore", ""); err == nil {
		t.Fatal("reduced conntrack below live occupancy")
	}
	put(s.path("net.netfilter.nf_conntrack_count"), "0\n")
	put(s.path(keys[2]), "45000\n")
	if _, err := s.execute("restore", ""); err == nil {
		t.Fatal("overwrote a conflicting manual edit")
	}
	put(s.path(keys[2]), fmt.Sprint(p.Settings[1].Target))
	p, err = s.execute("restore", "")
	if err != nil || p.Managed || p.Settings[0].Current != 129 || p.Settings[1].Current != 4096 {
		t.Fatalf("restore: %+v, %v", p, err)
	}
	if _, err := os.Stat(s.config); !os.IsNotExist(err) {
		t.Fatalf("expected no profile, got %v", err)
	}
}
