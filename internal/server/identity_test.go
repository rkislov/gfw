package server

import (
	"encoding/json"
	"testing"
)

func TestPersonalSessionCannotAdministerOrExportOtherProfiles(t *testing.T) {
	s, h := setup(t)
	if err := s.EnableIdentity(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer s.CloseIdentity()
	admin := map[string]string{"Authorization": "Bearer " + testToken}
	const body = `{"name":"alice","source":"local","role":"user","grants":["openvpn:alice"],"password":"alice test password"}`
	if w := request(h, "PUT", "/api/v1/users", body, admin); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	login := request(h, "POST", "/api/v1/auth/login", `{"username":"alice","password":"alice test password"}`, nil)
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	var auth map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Cookie": login.Result().Cookies()[0].String(), "X-GFW-CSRF": auth["csrf"]}
	for _, path := range []string{"/users", "/sysctl", "/config", "/wireguard/state"} {
		if w := request(h, "GET", "/api/v1"+path, "", hdr); w.Code != 403 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if w := request(h, "GET", "/api/v1/portal", "", hdr); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "POST", "/api/v1/portal/export", `{"id":"openvpn:bob"}`, hdr); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(h, "PUT", "/api/v1/users", `{"name":"alice","source":"local","role":"user","revision":1,"disabled":true}`, admin); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "GET", "/api/v1/portal", "", hdr); w.Code != 401 {
		t.Fatalf("disabled user's session remained valid: %d", w.Code)
	}
}
