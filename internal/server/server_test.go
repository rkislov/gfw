package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/store"
)

const testToken = "aabbccdd0000111122223333444455556666777788889999aaaabbbbccccdddd"

func setup(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db, testToken, "")
	return s, s.Handler()
}

func TestApplyUsesSavedRevisionAndAuditsBeforeAgent(t *testing.T) {
	s, h := setup(t)
	dir, err := os.MkdirTemp("/tmp", "gfw-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	remote := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/firewall" {
			_ = json.NewEncoder(w).Encode(agent.State{Enabled: true, History: []agent.Record{}})
			return
		}
		if r.URL.Path != "/v1/firewall/apply" {
			w.WriteHeader(404)
			return
		}
		calls.Add(1)
		var in agent.ApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
		}
		if in.Revision != 1 || in.Config.DefaultInput != "drop" || len(in.Config.Rules) != 0 {
			t.Error("agent received wrong saved snapshot", in)
		}
		events, err := s.Store.Audit(r.Context())
		if err != nil || len(events) != 1 || events[0].Action != "firewall.apply.request:change-api" {
			t.Error("privileged request dispatched before audit", events, err)
		}
		_ = json.NewEncoder(w).Encode(agent.Record{ID: in.ID, Revision: in.Revision, Status: "pending"})
	})}
	go remote.Serve(listener)
	defer remote.Close()
	s.AgentSocket = path
	headers := map[string]string{"Authorization": "Bearer " + testToken}
	if w := request(h, "POST", "/api/v1/changes/apply", `{"id":"change-api","revision":2,"timeout_seconds":120}`, headers); w.Code != 412 {
		t.Fatal("stale revision reached agent", w.Code)
	}
	if w := request(h, "POST", "/api/v1/changes/apply", `{"id":"change-api","revision":1,"timeout_seconds":120,"config":{}}`, headers); w.Code != 400 {
		t.Fatal("raw policy accepted from apply client", w.Code)
	}
	w := request(h, "POST", "/api/v1/changes/apply", `{"id":"change-api","revision":1,"timeout_seconds":120}`, headers)
	if w.Code != 200 || calls.Load() != 1 {
		t.Fatal(w.Code, calls.Load(), w.Body.String())
	}
	for _, path := range []string{"/api/v1/changes/apply", "/api/v1/changes/change-api/confirm", "/api/v1/changes/change-api/rollback"} {
		if w = request(h, "POST", path, "{}", nil); w.Code != 401 {
			t.Fatal("unprotected mutation", path, w.Code)
		}
	}
}
func request(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAuthenticationCSRFAndRevision(t *testing.T) {
	_, h := setup(t)
	if w := request(h, "GET", "/api/v1/interfaces", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := request(h, "POST", "/api/v1/auth/login", `{"token":"`+testToken+`"}`, nil)
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	var auth map[string]string
	if e := json.Unmarshal(login.Body.Bytes(), &auth); e != nil {
		t.Fatal(e)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure session cookie")
	}
	headers := map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value, "If-Match": `"1"`}
	body := `{"default_input":"drop","default_forward":"drop","rules":[]}`
	if w := request(h, "PUT", "/api/v1/config", body, headers); w.Code != 403 {
		t.Fatalf("CSRF missing status %d", w.Code)
	}
	headers["X-GFW-CSRF"] = auth["csrf"]
	headers["Origin"] = "https://attacker.invalid"
	if w := request(h, "PUT", "/api/v1/config", body, headers); w.Code != 403 {
		t.Fatal("cross origin allowed")
	}
	delete(headers, "Origin")
	w := request(h, "PUT", "/api/v1/config", body, headers)
	if w.Code != 200 || w.Header().Get("ETag") != `"2"` {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(h, "PUT", "/api/v1/config", body, headers); w.Code != 412 {
		t.Fatalf("stale revision status %d", w.Code)
	}
	delete(headers, "If-Match")
	if w = request(h, "PUT", "/api/v1/config", body, headers); w.Code != 428 {
		t.Fatal("missing precondition accepted")
	}
	if w = request(h, "POST", "/api/v1/auth/logout", "{}", headers); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request(h, "GET", "/api/v1/config", "", headers); w.Code != 401 {
		t.Fatal("logged out session reused")
	}
}
func TestPreviewDoesNotMutateConfig(t *testing.T) {
	_, h := setup(t)
	headers := map[string]string{"Authorization": "Bearer " + testToken}
	body := `{"default_input":"drop","default_forward":"drop","rules":[]}`
	w := request(h, "POST", "/api/v1/changes/plan", body, headers)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var plan struct {
		CanApply  bool   `json:"can_apply"`
		Validated bool   `json:"kernel_validated"`
		NFT       string `json:"nftables"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &plan)
	if plan.CanApply || plan.Validated || !strings.Contains(plan.NFT, "table inet gfw") {
		t.Fatal("invalid preview contract")
	}
	w = request(h, "GET", "/api/v1/config", "", headers)
	if w.Header().Get("ETag") != `"1"` {
		t.Fatal("preview changed revision")
	}
	w = request(h, "POST", "/api/v1/changes/plan", body+"{}", headers)
	if w.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	w = request(h, "POST", "/api/v1/changes/plan", `{"default_input":"drop","default_forward":"drop","rules":[],"command":"flush"}`, headers)
	if w.Code != 400 {
		t.Fatal("unknown field accepted")
	}
}
func TestAgentFailureAndLoginLimit(t *testing.T) {
	s, h := setup(t)
	s.AgentSocket = filepath.Join(t.TempDir(), "absent.sock")
	w := request(h, "GET", "/api/v1/interfaces", "", map[string]string{"Authorization": "Bearer " + testToken})
	if w.Code != 503 {
		t.Fatal("must not fall back to local inventory")
	}
	for range 10 {
		request(h, "POST", "/api/v1/auth/login", `{"token":"wrong"}`, nil)
	}
	if w = request(h, "POST", "/api/v1/auth/login", `{"token":"wrong"}`, nil); w.Code != 429 {
		t.Fatal("login not limited")
	}
}
func TestEmbeddedUI(t *testing.T) {
	_, h := setup(t)
	for _, path := range []string{"/", "/assets/app.js", "/assets/app.css"} {
		w := request(h, "GET", path, "", nil)
		b, _ := io.ReadAll(w.Result().Body)
		if w.Code != 200 || len(b) == 0 {
			t.Fatalf("missing asset %s: %d", path, w.Code)
		}
	}
}
