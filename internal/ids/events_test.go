package ids

import (
	"strings"
	"testing"
)

func TestPassiveRulesRejectInlineAndFileOptions(t *testing.T) {
	c := Config{Enabled: true, Interfaces: []string{"lan0"}, HomeNet: []string{"192.0.2.0/24"}}
	for _, rule := range []string{
		"drop udp any any -> any any (sid:1000001;)",
		"alert tcp any any -> any any (dataset:isset,name,load /etc/shadow; sid:1000001;)",
		"alert tcp any any -> any any (luajit:rules.lua; sid:1000001;)",
		"alert tcp any any -> any any (filestore; sid:1000001;)",
		"alert tcp any any -> any any (sid:1000001;)\\",
	} {
		c.Rules = rule
		if err := Validate(c); err == nil {
			t.Fatalf("unexpectedly allowed %q", rule)
		}
	}
	c.Rules = "# test\nalert udp any any -> $HOME_NET 53 (msg:\"Test\"; sid:1000001;)"
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}

func TestStoreKeepsOnlyAlertMetadata(t *testing.T) {
	raw := []byte(`{"event_type":"alert","in_iface":"lan0","timestamp":"2026-11-11T07:30:00.000001+0000","src_ip":"192.0.2.2","dest_ip":"192.0.2.1","src_port":42555,"dest_port":53,"proto":"UDP","payload":"private-payload","alert":{"signature_id":1000001,"severity":2,"signature":"Test"}}`)
	e, ok := parseAlert(raw, strings.Repeat("a", 64))
	if !ok || e.IFace != "lan0" || e.DstPort != 53 || e.At != "2026-11-11T07:30:00.000001Z" {
		t.Fatalf("bad event: %+v", e)
	}
	root := t.TempDir()
	db, err := openEvents(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeEvents(db, []Alert{e, e}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = openEvents(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	alerts, err := readEvents(db, 100, 2)
	if err != nil || len(alerts) != 1 || alerts[0].ID != 1 || alerts[0].Message != "Test" {
		t.Fatalf("bad cursor read: %+v, %v", alerts, err)
	}
	if _, ok := parseAlert([]byte(`{"event_type":"flow","payload":"private-payload"}`), ""); ok {
		t.Fatal("non-alert event accepted")
	}
}
