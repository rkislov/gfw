package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestServicesDraftPersistsWithIndependentRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gfw.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	draft, e := s.ReadServices(ctx)
	if e != nil {
		t.Fatal(e)
	}
	draft.Config.DNS.CacheSize = 12345
	if _, e = s.SaveServices(ctx, draft.Revision, draft.Config); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveServices(ctx, draft.Revision, draft.Config); !errors.Is(e, ErrConflict) {
		t.Fatal("stale service draft overwritten", e)
	}
	fw, e := s.Read(ctx)
	if e != nil || fw.Revision != 1 {
		t.Fatal("service save changed firewall revision", e)
	}
	events, e := s.Audit(ctx)
	if e != nil || len(events) != 1 || events[0].Action != "services.draft.save" {
		t.Fatal("service audit not atomic", events, e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	draft, e = s.ReadServices(ctx)
	if e != nil || draft.Revision != 2 || draft.Config.DNS.CacheSize != 12345 || draft.Config.DNS.Enabled || draft.Config.DHCP.Enabled {
		t.Fatal("service settings lost or activated by saving", draft, e)
	}
}
