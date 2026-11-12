package siem

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCEFEscaping(t *testing.T) {
	line := Event("gfw", "2026-11-12T10:30:00Z", "0.22.4", "sig|id", "test\\name", 6,
		Field{"msg", "a=b\r\nc\\d|ё"})
	want := `<134>1 2026-11-12T10:30:00Z gfw gfw - - - CEF:0|GFW|GFW NGFW|0.22.4|sig\|id|test\\name|6|msg=a\=b\r\nc\\d|ё`
	if line != want {
		t.Fatalf("%q != %q", line, want)
	}
}

func TestTLSSyslogValidatesCertificate(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	receiver := tls.NewListener(listener, fixture.TLS.Clone())
	defer receiver.Close()
	result := make(chan string, 1)
	go func() {
		for range 2 {
			conn, err := receiver.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			var count int
			if _, err := fmt.Fscanf(reader, "%d ", &count); err == nil && count < 4096 {
				msg := make([]byte, count)
				if _, err := io.ReadFull(reader, msg); err == nil {
					result <- string(msg)
				}
			}
			_ = conn.Close()
		}
	}()
	dest := Destination{Address: receiver.Addr().String(), Transport: "tls"}
	message := Event("gfw", "2026-11-12T10:30:00Z", "test", "event", "Тест", 3)
	if err := dest.Send(t.Context(), []string{message}); err == nil {
		t.Fatal("accepted unknown CA")
	}
	dest.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}))
	if err := dest.Send(t.Context(), []string{message}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if message != got {
			t.Fatal(got)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("receiver timeout")
	}
}
