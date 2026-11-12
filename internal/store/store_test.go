package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rkislov/gfw/internal/policy"
)

func TestLegacyMigrationPreservesFilteringAndSavesObjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`UPDATE schema_version SET version=1; UPDATE config SET body='{"default_input":"drop","default_forward":"drop","rules":[]}'`)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	x, err := s.Read(context.Background())
	if err != nil || x.Config.Stateful {
		t.Fatal("legacy filtering changed", err)
	}
	x.Config.Zones = []policy.Zone{{ID: "lan", Name: "LAN", Kind: "lan", Interfaces: []string{"eth0"}}}
	x.Config.AddressGroups = []policy.AddressGroup{{ID: "hosts", Name: "Hosts", Family: "ipv4", Networks: []string{"192.0.2.5/32"}}}
	if _, err = s.Save(context.Background(), x.Revision, x.Config); err != nil {
		t.Fatal(err)
	}
	x, err = s.Read(context.Background())
	if err != nil || len(x.Config.Zones) != 1 || len(x.Config.AddressGroups) != 1 || x.Config.Stateful {
		t.Fatal("objects or legacy mode lost", x, err)
	}
}

func TestConcurrentCompareAndSwapAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	initial, err := s.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Save(ctx, initial.Revision, initial.Config); results <- e }()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for e := range results {
		if e == nil {
			successes++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	events, err := s.Audit(ctx)
	if err != nil || len(events) != 1 || events[0].Revision != 2 {
		t.Fatal("audit not atomic with save", events, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Read(ctx)
	if err != nil || snap.Revision != 2 {
		t.Fatal("revision not persisted", snap, err)
	}
}
