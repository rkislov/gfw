package store

import (
	"path/filepath"
	"testing"

	"github.com/rkislov/gfw/internal/traffic"
)

func TestSIEMTrafficUpgradeAndDurableQueue(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := SIEM{Enabled: true, Revision: 1, Address: "siem.example.org:6514", Transport: "tls"}
	if err := db.SaveSIEM(ctx, legacy, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.AdvanceSIEM(ctx, 2, 13, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("DROP TABLE siem_traffic; DROP TABLE siem_traffic_queue"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := db.ReadSIEM(ctx)
	if err != nil || cfg.Address != legacy.Address || cfg.AuditCursor != 13 || cfg.IDSCursor != 42 || cfg.Traffic.Enabled() {
		t.Fatal(cfg, err)
	}
	udp := uint8(17)
	cfg.Traffic = &traffic.ExportFilter{Conntrack: []string{"destroy"}, NFLOG: []string{"drop"}, IP: "2001:db8::/32", Port: 443,
		Protocol: &udp, Rule: "blocked", Direction: "forward"}
	if err := db.SaveSIEM(ctx, cfg, "admin"); err != nil {
		t.Fatal(err)
	}
	events := []traffic.Event{
		{EventID: "ct", Kind: "destroy", ReplySource: "2001:db8::1", ReplyDestinationPort: 443, Protocol: 17},
		{EventID: "allowed", Kind: "rule", Action: "accept", Source: "2001:db8::2", DestinationPort: 443, Protocol: 17},
		{EventID: "wrong-rule", Kind: "rule", Action: "drop", Rule: "other", Direction: "forward", Source: "2001:db8::2", DestinationPort: 443, Protocol: 17},
		{EventID: "drop", Kind: "rule", Action: "drop", Rule: "blocked", Direction: "forward", Source: "2001:db8::2", DestinationPort: 443, Protocol: 17},
		{EventID: "wrong-protocol", Kind: "destroy", Source: "2001:db8::2", DestinationPort: 443, Protocol: 6},
	}
	for range 2 {
		if err := db.EnqueueSIEMTraffic(ctx, events); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	batch, err := db.PeekSIEMTraffic(ctx)
	if err != nil || len(batch.Events) != 2 || batch.Events[0].EventID != "ct" || batch.Events[1].EventID != "drop" {
		t.Fatal(batch, err)
	}
	if err := db.AckSIEMTraffic(ctx, 2, batch.Cursor, true); err != nil {
		t.Fatal(err)
	}
	stats, err := db.SIEMTrafficStats(ctx)
	if err != nil || stats.Queued != 2 || stats.LastSent != "" {
		t.Fatal(stats, err)
	}
	if err := db.AckSIEMTraffic(ctx, 3, batch.Cursor, true); err != nil {
		t.Fatal(err)
	}
	stats, err = db.SIEMTrafficStats(ctx)
	if err != nil || stats.Queued != 0 || stats.LastSent == "" {
		t.Fatal(stats, err)
	}
}
