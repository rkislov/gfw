package openvpn

import (
	"strings"
	"testing"
)

func sample() Profile {
	return Profile{ID: strings.Repeat("1", 32), Name: "Office", ServerCertificateID: strings.Repeat("2", 32), ClientCertificateID: strings.Repeat("3", 32), Remote: "vpn.example.org", Port: 1194, Protocol: "udp", Routes: []string{"10.50.0.0/24"}, DNS: []string{"10.50.0.1"}}
}
func TestStructuredProfileRejectsInjectionAndInvalidAddresses(t *testing.T) {
	for _, mutate := range []func(*Profile){
		func(p *Profile) { p.Remote = "vpn.example.org\nup /bin/sh" }, func(p *Profile) { p.Remote = "host;command" }, func(p *Profile) { p.Remote = "https://vpn.example.org" }, func(p *Profile) { p.Remote = "999.0.0.1" }, func(p *Profile) { p.Remote = "0.0.0.0" }, func(p *Profile) { p.Remote = "fe80::1%lan0" }, func(p *Profile) { p.Protocol = "udp\nplugin /tmp/a.so" }, func(p *Profile) { p.Port = 0 }, func(p *Profile) { p.Routes = []string{"0.0.0.0/0"} }, func(p *Profile) { p.Routes = []string{"10.50.0.1/24"} }, func(p *Profile) { p.Routes = []string{"224.0.0.0/4"} },
		func(p *Profile) { p.Routes = []string{"112.0.0.0/3"} },
		func(p *Profile) { p.DNS = []string{"240.0.0.1"} }, func(p *Profile) { p.Routes = []string{"10.0.0.0/8\nup /bin/sh"} }, func(p *Profile) { p.DNS = []string{"10.0.0.1\nscript-security 3"} }, func(p *Profile) { p.DNS = []string{"::1"} }, func(p *Profile) { p.ID = "../../key" },
	} {
		p := sample()
		mutate(&p)
		if ValidateProfile(p) == nil {
			t.Errorf("accepted invalid profile: %+v", p)
		}
	}
	for _, host := range []string{"vpn.example.org", "198.51.100.10", "2001:db8::10", "vpn"} {
		p := sample()
		p.Remote = host
		if e := ValidateProfile(p); e != nil {
			t.Fatal(host, e)
		}
	}
	c := Config{Profiles: []Profile{sample(), sample()}}
	if Validate(c) == nil {
		t.Fatal("duplicate IDs accepted")
	}
}
func TestRenderPinsServerAndRestrictsPushes(t *testing.T) {
	p := sample()
	p.Protocol = "tcp"
	p.Name = "Untrusted display name <key>"
	raw, e := Render(p, []byte("CA"), []byte("CLIENT"), []byte("CLIENT-SECRET"), strings.Repeat("ab", 32))
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"proto tcp-client\n", "remote vpn.example.org 1194\n", "remote-cert-tls server\n", "peer-fingerprint " + strings.TrimSuffix(strings.Repeat("ab:", 32), ":") + "\n", "route-nopull\n", "route 10.50.0.0 255.255.255.0\n", "allow-compression no\n", "<key>\nCLIENT-SECRET\n</key>"} {
		if !strings.Contains(raw, want) {
			t.Error("missing", want)
		}
	}
	if strings.Contains(raw, p.Name) || strings.Contains(raw, "redirect-gateway") {
		t.Fatal("unexpected directive")
	}
}
func FuzzProfileInputs(f *testing.F) {
	for _, s := range []string{"vpn.example.org", "host\nplugin /tmp/x", "198.51.100.10", "2001:db8::10"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := sample()
		p.Remote = s
		if ValidateProfile(p) == nil {
			raw, e := Render(p, []byte("CA"), []byte("CLIENT"), []byte("KEY"), strings.Repeat("ab", 32))
			if e != nil || strings.Count(raw, "\nremote ") != 1 || strings.ContainsAny(s, "\r\n\x00 \t") {
				t.Fatal("unsafe remote accepted")
			}
		}
	})
}
