package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestWireGuardDraftHasIndependentRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	draft, e := s.ReadWireGuard(ctx)
	if e != nil || draft.Config.Tunnels == nil {
		t.Fatal(e)
	}
	if _, e = s.SaveWireGuard(ctx, draft.Revision, draft.Config); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveWireGuard(ctx, draft.Revision, draft.Config); !errors.Is(e, ErrConflict) {
		t.Fatal("stale WG draft accepted", e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	draft, e = s.ReadWireGuard(ctx)
	if e != nil || draft.Revision != 2 {
		t.Fatal("WG revision lost", e)
	}
	fw, e := s.Read(ctx)
	if e != nil || fw.Revision != 1 {
		t.Fatal("WG save changed firewall revision", e)
	}
}
