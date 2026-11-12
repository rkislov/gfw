package ipsec

import "testing"

func TestEstablishedPeers(t *testing.T) {
	details := `gfw-lab: #1, ESTABLISHED, IKEv2, a b
  remote 'gateway.example.net' @ 192.0.2.2[4500] EAP: 'alice'
  gfw-lab: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
gfw-lab: #2, ESTABLISHED, IKEv2, a b
  remote 'bob.example.net' @ 192.0.2.3[4500]
gfw-lab: #3, CONNECTING, IKEv2, a b
  gfw-lab: #3, reqid 3, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
gfw-lab: #4, ESTABLISHED, IKEv2, a b
  remote 'remote-gateway.example.net' @ 192.0.2.4[4500]
  gfw-lab: #4, reqid 4, INSTALLED, TUNNEL, ESP:AES_GCM_16-256`
	got := establishedPeers(details)
	if len(got) != 2 || got[0] != (PeerSession{Identity: "gateway.example.net", Username: "alice"}) ||
		got[1] != (PeerSession{Identity: "remote-gateway.example.net"}) {
		t.Fatal(got)
	}
}
