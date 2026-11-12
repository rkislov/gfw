//go:build linux

package pki

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This test creates network devices only in an explicitly opted-in disposable
// privileged ALT p10 container. It never runs during ordinary go test.
func TestOpenVPNRealClientProfile(t *testing.T) {
	if os.Getenv("GFW_OPENVPN_LAB") != "1" {
		t.Skip("requires disposable privileged OpenVPN lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("lab requires root")
	}
	run := func(args ...string) string {
		t.Helper()
		out, e := exec.Command(args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %v: %s", args, e, out)
		}
		return string(out)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "netns", "add", "gfw-ovpn-test")
	defer exec.Command("ip", "netns", "del", "gfw-ovpn-test").Run()
	run("ip", "link", "add", "ovpn-host", "type", "veth", "peer", "name", "ovpn-peer")
	defer exec.Command("ip", "link", "del", "ovpn-host").Run()
	run("ip", "link", "set", "ovpn-peer", "netns", "gfw-ovpn-test")
	run("ip", "addr", "add", "198.18.240.1/30", "dev", "ovpn-host")
	run("ip", "link", "set", "ovpn-host", "up")
	run("ip", "netns", "exec", "gfw-ovpn-test", "ip", "addr", "add", "198.18.240.2/30", "dev", "ovpn-peer")
	run("ip", "netns", "exec", "gfw-ovpn-test", "ip", "link", "set", "ovpn-peer", "up")
	run("ip", "netns", "exec", "gfw-ovpn-test", "ip", "link", "set", "lo", "up")
	root := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	start := func(log string, args ...string) func() {
		t.Helper()
		f, e := os.OpenFile(filepath.Join(root, log), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = f
		cmd.Stderr = f
		if e = cmd.Start(); e != nil {
			f.Close()
			t.Fatal(e)
		}
		stopped := false
		return func() {
			if !stopped {
				stopped = true
				cmd.Process.Kill()
				cmd.Wait()
				f.Close()
			}
		}
	}
	waitLog := func(name, needle string, timeout time.Duration) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			raw, _ := os.ReadFile(filepath.Join(root, name))
			if strings.Contains(string(raw), needle) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		raw, _ := os.ReadFile(filepath.Join(root, name))
		t.Fatalf("%s missing %q: %s", name, needle, raw)
	}
	m := testVault(t)
	p, ca, server, client := vpnFixture(t, m)
	p.Remote = "198.18.240.1"
	p.Port = 41194
	p.Routes = []string{"10.50.0.0/24"}
	// A private server fixture is accessed only inside the PKI package test,
	// never through a production HTTP export endpoint.
	issuer, e := m.get(ca.ID)
	if e != nil {
		t.Fatal(e)
	}
	srv, e := m.get(server.ID)
	if e != nil {
		t.Fatal(e)
	}
	crl, e := m.CRL(ca.ID)
	if e != nil {
		t.Fatal(e)
	}
	caFile := write("ca.pem", issuer.PEM)
	certFile := write("server.pem", srv.PEM)
	keyFile := write("server.key", srv.Key)
	crlFile := write("crl.pem", crl)
	cfg := fmt.Sprintf("dev ovpnsrvtest\ndev-type tun\nproto udp\nlocal 198.18.240.1\nport 41194\ntopology subnet\nserver 10.50.0.0 255.255.255.0\nca %s\ncert %s\nkey %s\ncrl-verify %s\ndh none\nremote-cert-tls client\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\nallow-compression no\ndisable-dco\npush \"route 203.0.113.0 255.255.255.0\"\npush \"redirect-gateway def1\"\nverb 3\n", caFile, certFile, keyFile, crlFile)
	serverConfig := write("server.conf", []byte(cfg))
	stopServer := start("server.log", "/usr/sbin/openvpn", "--config", serverConfig)
	defer stopServer()
	waitLog("server.log", "Initialization Sequence Completed", 10*time.Second)
	raw, e := m.ExportOpenVPN(p)
	if e != nil {
		t.Fatal(e)
	}
	clientConfig := write("client.ovpn", []byte(raw+"dev ovpncltest\ndev-type tun\ndisable-dco\n"))
	stopClient := start("client.log", "ip", "netns", "exec", "gfw-ovpn-test", "/usr/sbin/openvpn", "--config", clientConfig)
	defer stopClient()
	waitLog("client.log", "Initialization Sequence Completed", 15*time.Second)
	run("ip", "netns", "exec", "gfw-ovpn-test", "ping", "-c", "2", "-W", "2", "10.50.0.1")
	t.Log("PASS: exported .ovpn establishes actual TLS/AES-GCM tunnel and passes encrypted ICMP on ALT p10")

	routes := run("ip", "netns", "exec", "gfw-ovpn-test", "ip", "route", "show")
	if strings.Contains(routes, "203.0.113.0") || strings.Contains(routes, "0.0.0.0/1") || strings.Contains(routes, "128.0.0.0/1") || strings.Contains(routes, "default") {
		t.Fatal("remote route push accepted", routes)
	}
	t.Log("PASS: route-nopull ignores server route and redirect-gateway pushes")
	stopClient()
	stopServer()
	p.Protocol = "tcp"
	tcpProfile, e := m.ExportOpenVPN(p)
	if e != nil {
		t.Fatal(e)
	}
	tcpClientConfig := write("tcp-client.ovpn", []byte(tcpProfile+"dev ovpncltest\ndev-type tun\ndisable-dco\n"))
	tcpServerConfig := write("tcp-server.conf", []byte(strings.Replace(cfg, "proto udp\n", "proto tcp-server\n", 1)))
	stopServer = start("tcp-server.log", "/usr/sbin/openvpn", "--config", tcpServerConfig)
	defer stopServer()
	waitLog("tcp-server.log", "Initialization Sequence Completed", 10*time.Second)
	stopClient = start("tcp-client.log", "ip", "netns", "exec", "gfw-ovpn-test", "/usr/sbin/openvpn", "--config", tcpClientConfig)
	defer stopClient()
	waitLog("tcp-client.log", "Initialization Sequence Completed", 15*time.Second)
	run("ip", "netns", "exec", "gfw-ovpn-test", "ping", "-c", "1", "-W", "2", "10.50.0.1")
	t.Log("PASS: exported TCP client profile also establishes tunnel and passes encrypted ICMP")
	p.Protocol = "udp"

	stopClient()
	// Pin another valid leaf signed by the very same CA. This must fail, proving
	// the profile does more than accept any server certificate from the issuer.
	other := testLeaf(t, m, ca, "other.home.arpa")
	srv, e = m.get(other.ID)
	if e != nil {
		t.Fatal(e)
	}
	stopServer()
	write("server.pem", srv.PEM)
	write("server.key", srv.Key)
	stopServer = start("wrong-server.log", "/usr/sbin/openvpn", "--config", serverConfig)
	defer stopServer()
	waitLog("wrong-server.log", "Initialization Sequence Completed", 10*time.Second)
	stopClient = start("wrong-client.log", "ip", "netns", "exec", "gfw-ovpn-test", "/usr/sbin/openvpn", "--config", clientConfig)
	defer stopClient()
	waitLog("wrong-client.log", "certificate hash verification failed", 10*time.Second)
	time.Sleep(time.Second)
	log, _ := os.ReadFile(filepath.Join(root, "wrong-client.log"))
	if strings.Contains(string(log), "Initialization Sequence Completed") {
		t.Fatal("client accepted other same-CA server")
	}
	t.Log("PASS: exact server fingerprint rejects replacement same-CA certificate")
	stopClient()
	stopServer()
	srv, _ = m.get(server.ID)
	write("server.pem", srv.PEM)
	write("server.key", srv.Key)
	if _, e = m.Revoke(client.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = m.ExportOpenVPN(p); e == nil {
		t.Fatal("revoked client re-exported")
	}
	crl, e = m.CRL(ca.ID)
	if e != nil {
		t.Fatal(e)
	}
	write("crl.pem", crl)
	stopServer = start("revoked-server.log", "/usr/sbin/openvpn", "--config", serverConfig)
	defer stopServer()
	waitLog("revoked-server.log", "Initialization Sequence Completed", 10*time.Second)
	stopClient = start("revoked-client.log", "ip", "netns", "exec", "gfw-ovpn-test", "/usr/sbin/openvpn", "--config", clientConfig)
	defer stopClient()
	waitLog("revoked-server.log", "certificate revoked", 10*time.Second)
	log, _ = os.ReadFile(filepath.Join(root, "revoked-client.log"))
	if strings.Contains(string(log), "Initialization Sequence Completed") {
		t.Fatal("server accepted revoked client")
	}
	t.Log("PASS: refreshed CRL on server rejects previously issued client profile")
}
