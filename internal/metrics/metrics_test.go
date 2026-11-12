package metrics

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLinuxSample(t *testing.T) {
	stat := []byte("cpu  1 2 3 4 5 6 7 8 200 300\ncpu0 1 2 3 4")
	mem := []byte("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB")
	dev := []byte("Inter-| Receive | Transmit\nlan0: 9007199254740993 2 3 4 5 6 7 8 42 10 11 12 13 14 15 16")
	got, err := parse(stat, mem, dev, []byte("123.25 37.80"))
	if err != nil {
		t.Fatal(err)
	}
	if got.CPU != (CPU{Total: 36, Idle: 9}) || got.MemoryTotal != 1024000 || got.MemoryAvailable != 256000 ||
		got.UptimeMS != 123250 || len(got.Interfaces) != 1 || got.Interfaces[0] != (Interface{Name: "lan0", RX: 9007199254740993, TX: 42}) {
		t.Fatalf("unexpected metrics: %+v", got)
	}
	b, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(b), `"rx_bytes":"9007199254740993"`) {
		t.Fatalf("loss of counter precision: %s (%v)", b, err)
	}
}

func TestRejectMissingAvailableMemory(t *testing.T) {
	_, err := parse([]byte("cpu  1 2 3 4 5 6 7 8"), []byte("MemTotal: 1000 kB"), nil, nil)
	if err == nil {
		t.Fatal("accepted missing MemAvailable")
	}
}
