package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/vpncred"
)

func TestVPNDisconnectAuditAndCEF(t *testing.T) {
	s, handler := setup(t)
	dir, err := os.MkdirTemp("/tmp", "gfw-vpn-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s.AgentSocket = filepath.Join(dir, "a.sock")
	agent, err := net.Listen("unix", s.AgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	profile := strings.Repeat("a", 32)
	remote := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/v1/ids/alerts" && r.URL.Query().Get("after") == "0" {
			_ = json.NewEncoder(w).Encode([]ids.Alert{{
				ID: 23, At: "2026-11-12T10:30:00Z", SID: 1001, Severity: 1, Action: "blocked",
				Src: "192.0.2.1", Dst: "198.51.100.1", SrcPort: 1234, DstPort: 443,
				Protocol: "TCP", IFace: "wan0", Message: "Fixture signature",
			}})
			return
		}
		var req vpncred.DisconnectRequest
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&req) != nil ||
			req.ProfileID != profile || req.SessionID == nil || *req.SessionID != 0 || req.User != "alice" {
			t.Error("wrong agent request", req, r.URL)
			w.WriteHeader(400)
			return
		}
		protocol := strings.Split(r.URL.Path, "/")[3]
		events, err := s.Store.Audit(r.Context())
		if err != nil || len(events) == 0 || events[0].Action != "vpn.disconnect."+protocol+".request:"+profile+":0:alice" {
			t.Error("audit intent must precede the agent call", events, err)
		}
		if protocol == "ipsec" {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"session gone"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	})}
	go remote.Serve(agent)
	defer remote.Close()
	body := fmt.Sprintf(`{"profile_id":%q,"session_id":0,"user":"alice"}`, profile)
	if w := request(handler, "POST", "/api/v1/vpn/openvpn/disconnect", body, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	auth := map[string]string{"Authorization": "Bearer " + testToken}
	for protocol, status := range map[string]int{"openvpn": 200, "ipsec": 409} {
		if w := request(handler, "POST", "/api/v1/vpn/"+protocol+"/disconnect", body, auth); w.Code != status {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	events, err := s.Store.AuditAfter(t.Context(), 0)
	if err != nil || len(events) != 4 {
		t.Fatal(events, err)
	}

	receiver, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	received := make(chan []string, 1)
	go func() {
		var frames []string
		for range 2 {
			conn, err := receiver.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			for {
				var n int
				if _, err := fmt.Fscanf(reader, "%d ", &n); err != nil {
					break
				}
				message := make([]byte, n)
				if _, err := io.ReadFull(reader, message); err != nil {
					break
				}
				frames = append(frames, string(message))
			}
			_ = conn.Close()
		}
		received <- frames
	}()
	config := fmt.Sprintf(`{"revision":1,"enabled":true,"address":%q,"transport":"tcp","ca_pem":""}`, receiver.Addr())
	if w := request(handler, "PUT", "/api/v1/siem", config, auth); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cfg, err := s.Store.ReadSIEM(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.forwardAudit(t.Context(), cfg, "lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.forwardIDS(t.Context(), cfg, "lab"); err != nil {
		t.Fatal(err)
	}
	select {
	case frames := <-received:
		joined := strings.Join(frames, "\n")
		if len(frames) != 6 || !strings.Contains(joined, "|vpn.disconnect.openvpn.success|") ||
			!strings.Contains(joined, "|vpn.disconnect.ipsec.failed|") ||
			!strings.Contains(joined, "suser=admin") || !strings.Contains(joined, "duser=alice") ||
			!strings.Contains(joined, "|suricata.1001|Fixture signature|8|externalId=23 src=192.0.2.1") {
			t.Fatal(frames)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("CEF receiver timeout")
	}
	cfg, err = s.Store.ReadSIEM(context.Background())
	if err != nil || cfg.AuditCursor != 5 || cfg.IDSCursor != 23 {
		t.Fatal(cfg, err)
	}
}
