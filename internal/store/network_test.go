package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rkislov/gfw/internal/netconfig"
)

func TestNetworkDraftHasIndependentRevisionAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snap, err := s.ReadNetwork(ctx)
	if err != nil || snap.Revision != 1 {
		t.Fatal(snap, err)
	}
	c := netconfig.Config{Interfaces: []netconfig.Link{{Name: "v100", Type: "vlan", Parent: "eth0", VLAN: 100, MTU: 1500, Up: true, Addresses: []string{"2001:0DB8:0:0::1/64"}}}, Routes: []netconfig.Route{}}
	saved, err := s.SaveNetwork(ctx, 1, c)
	if err != nil || saved.Revision != 2 || saved.Config.Interfaces[0].Addresses[0] != "2001:db8::1/64" {
		t.Fatal(saved, err)
	}
	if _, err = s.SaveNetwork(ctx, 1, c); !errors.Is(err, ErrConflict) {
		t.Fatal("stale network write accepted", err)
	}
	fw, err := s.Read(ctx)
	if err != nil || fw.Revision != 1 {
		t.Fatal("network save changed firewall revision")
	}
	events, err := s.Audit(ctx)
	if err != nil || len(events) != 1 || events[0].Action != "network.draft.save" {
		t.Fatal(events, err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err = s.ReadNetwork(ctx)
	if err != nil || snap.Revision != 2 || len(snap.Config.Interfaces) != 1 {
		t.Fatal("network state not durable", err)
	}
}
