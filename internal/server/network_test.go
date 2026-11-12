package server

import (
	"strings"
	"testing"
)

func TestNetworkRoutesAreAuthenticatedAndRevisionProtected(t *testing.T) {
	_, h := setup(t)
	headers := map[string]string{"Authorization": "Bearer " + testToken, "If-Match": `"1"`}
	body := `{"interfaces":[{"name":"v100","type":"vlan","parent":"eth0","vlan":100,"members":[],"bond_mode":"","mtu":1500,"up":true,"addresses":["192.0.2.1/24"],"adopt":false}],"routes":[]}`
	for _, path := range []string{"/api/v1/network/config", "/api/v1/network/state"} {
		if w := request(h, "GET", path, "", nil); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/network/plan", "/api/v1/network/apply", "/api/v1/network/changes/change-net/confirm", "/api/v1/network/changes/change-net/rollback"} {
		if w := request(h, "POST", path, "{}", nil); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	if w := request(h, "PUT", "/api/v1/network/config", body, headers); w.Code != 200 || w.Header().Get("ETag") != `"2"` {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(h, "PUT", "/api/v1/network/config", body, headers); w.Code != 412 {
		t.Fatal("stale network revision accepted", w.Code)
	}
	if w := request(h, "POST", "/api/v1/network/plan", body, headers); w.Code != 200 || !strings.Contains(w.Body.String(), "VID=100") || !strings.Contains(w.Body.String(), `"can_apply":false`) {
		t.Fatal("invalid offline plan", w.Body.String())
	}
	if w := request(h, "POST", "/api/v1/network/apply", `{"id":"change-net","revision":2,"timeout_seconds":120}`, headers); w.Code != 503 {
		t.Fatal("offline mutation accepted", w.Code)
	}
	if w := request(h, "GET", "/api/v1/config", "", headers); w.Header().Get("ETag") != `"1"` {
		t.Fatal("network changed firewall revision")
	}
}
