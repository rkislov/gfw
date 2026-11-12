package ipsec

import (
	"strconv"
	"strings"
)

// establishedPeers reads the human-readable swanctl --list-sas output already
// used for tunnel status. A row must have an established IKE SA and an installed
// CHILD SA in the same block.
func establishedPeers(details string) []PeerSession {
	var peers []PeerSession
	var peer PeerSession
	var established, installed bool
	finish := func() {
		if established && installed {
			peers = append(peers, peer)
		}
	}
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "gfw-") {
			finish()
			peer = PeerSession{}
			_, id, _ := strings.Cut(line, ": #")
			id, state, _ := strings.Cut(id, ", ")
			number, err := strconv.ParseUint(id, 10, 32)
			established = err == nil && strings.HasPrefix(state, "ESTABLISHED,")
			peer.IKEID = uint32(number)
			installed = false
			continue
		}
		line = strings.TrimSpace(line)
		if identity, ok := strings.CutPrefix(line, "remote '"); ok {
			peer.Identity, _, _ = strings.Cut(identity, "' @ ")
			if _, username, ok := strings.Cut(line, " EAP: '"); ok {
				peer.Username, _, _ = strings.Cut(username, "'")
			}
		}
		if strings.Contains(line, ", INSTALLED,") {
			installed = true
		}
	}
	finish()
	return peers
}
