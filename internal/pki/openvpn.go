package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/rkislov/gfw/internal/openvpn"
)

// OpenVPNIdentity is safe public metadata for the profile editor.
type OpenVPNIdentity struct {
	CAID              string `json:"ca_id"`
	ServerCommonName  string `json:"server_common_name"`
	ClientCommonName  string `json:"client_common_name"`
	ServerFingerprint string `json:"server_fingerprint"`
}

// openVPNPair must be called under m.mu, so revocation cannot race validation
// and the audit transaction preceding private export.
func (m *Manager) openVPNPair(p openvpn.Profile) (OpenVPNIdentity, entry, entry, entry, error) {
	var identity OpenVPNIdentity
	var server, client, root entry
	fail := func(e error) (OpenVPNIdentity, entry, entry, entry, error) {
		return identity, entry{}, entry{}, entry{}, e
	}
	if e := openvpn.ValidateProfile(p); e != nil {
		return fail(e)
	}
	var e error
	server, e = m.get(p.ServerCertificateID)
	if e != nil {
		return fail(e)
	}
	cert := p.Auth == nil || p.Auth.Certificate
	if cert {
		client, e = m.get(p.ClientCertificateID)
		if e != nil {
			return fail(e)
		}
		if client.Kind != "local" || client.Usage != "client" || server.CAID != client.CAID || client.RevokedAt != nil {
			return fail(errors.New("нужен действующий клиентский сертификат того же CA"))
		}
	}
	if server.Kind != "local" || server.Usage != "server" || server.CAID == "" || server.RevokedAt != nil {
		return fail(errors.New("нужен действующий серверный сертификат локального CA"))
	}
	root, e = m.get(server.CAID)
	if e != nil {
		return fail(e)
	}
	if root.Kind != "ca" {
		return fail(errors.New("нужен локальный CA"))
	}
	block, _ := pem.Decode(root.PEM)
	if block == nil {
		return fail(errors.New("повреждён CA"))
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return fail(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, x := range []struct {
		entry entry
		usage x509.ExtKeyUsage
	}{{server, x509.ExtKeyUsageServerAuth}, {client, x509.ExtKeyUsageClientAuth}} {
		if x.usage == x509.ExtKeyUsageClientAuth && !cert {
			continue
		}
		pair, e := validatePair(x.entry.PEM, x.entry.Key, m.now())
		if e != nil {
			return fail(e)
		}
		if _, e = pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: m.now(), KeyUsages: []x509.ExtKeyUsage{x.usage}}); e != nil {
			return fail(fmt.Errorf("сертификат VPN: %w", e))
		}
		if x.usage == x509.ExtKeyUsageServerAuth {
			identity.ServerCommonName = pair.Leaf.Subject.CommonName
		} else {
			identity.ClientCommonName = pair.Leaf.Subject.CommonName
		}
	}
	identity.CAID = root.ID
	identity.ServerFingerprint = server.Fingerprint
	return identity, server, client, root, nil
}
func (m *Manager) CheckOpenVPN(p openvpn.Profile) (OpenVPNIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, _, _, _, e := m.openVPNPair(p)
	return v, e
}

// ExportOpenVPN is the only PKI API that releases a local client private key.
// Server and CA keys are never included; only a client-auth leaf is eligible.
// Audit must commit before any private bytes are returned to the caller.
func (m *Manager) ExportOpenVPN(p openvpn.Profile) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	identity, _, client, root, e := m.openVPNPair(p)
	if e != nil {
		return "", e
	}
	// Include the leaf only, with its CA in the separate <ca> block.
	var leaf []byte
	if len(client.PEM) > 0 {
		block, _ := pem.Decode(client.PEM)
		if block == nil {
			return "", errors.New("повреждён клиентский сертификат")
		}
		leaf = pem.EncodeToMemory(block)
	}
	profile, e := openvpn.Render(p, root.PEM, leaf, client.Key, identity.ServerFingerprint)
	if e != nil {
		return "", e
	}
	tx, e := m.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if e = audit(tx, "pki.openvpn.client.private_export", p.ID+":"+client.ID, m.now()); e == nil {
		e = tx.Commit()
	}
	if e != nil {
		return "", e
	}
	return profile, nil
}

// OpenVPNMaterial is an internal controller-agent consumer, not an HTTP private
// key export. The CA signing key and peer private keys never leave this vault.
func (m *Manager) OpenVPNMaterial(i openvpn.Instance) (openvpn.Material, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := openvpn.Material{Instance: i, Peers: map[string][]byte{}}
	if e := openvpn.ValidateInstance(i); e != nil {
		return out, e
	}
	own, e := m.get(i.CertificateID)
	if e != nil {
		return out, e
	}
	role := "server"
	if i.Mode == "client" {
		role = "client"
	}
	if own.Kind != "local" || own.Usage != role || own.RevokedAt != nil {
		return out, errors.New("нужен действующий сертификат локального CA правильного назначения")
	}
	if _, e = validatePair(own.PEM, own.Key, m.now()); e != nil {
		return out, e
	}
	root, e := m.get(own.CAID)
	if e != nil {
		return out, e
	}
	if root.Kind != "ca" {
		return out, errors.New("нужен локальный CA")
	}
	out.CAID = root.ID
	out.CA = root.PEM
	out.Certificate = own.PEM
	out.Key = own.Key
	peers := []string{}
	if i.Mode == "client" {
		peers = append(peers, i.ServerCertificateID)
	} else {
		for _, c := range i.Clients {
			if c.CertificateID != "" {
				peers = append(peers, c.CertificateID)
			}
		}
	}
	peerRole := "client"
	if i.Mode == "client" {
		peerRole = "server"
	}
	for _, id := range peers {
		peer, e := m.get(id)
		if e != nil {
			return out, e
		}
		if peer.Kind != "local" || peer.CAID != root.ID || peer.Usage != peerRole {
			return out, errors.New("сертификат peer должен принадлежать тому же локальному CA и иметь правильное назначение")
		}
		if i.Mode == "client" && peer.RevokedAt != nil {
			return out, errors.New("сертификат удалённого сервера отозван")
		}
		out.Peers[id] = peer.PEM
	}
	out.CRL, e = m.crlLocked(root.ID)
	return out, e
}
func (m *Manager) OpenVPNCRL(id string) (openvpn.CRLUpdate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := openvpn.CRLUpdate{CAID: id}
	root, e := m.get(id)
	if e != nil {
		return out, e
	}
	if root.Kind != "ca" {
		return out, errors.New("нужен локальный CA")
	}
	out.CA = root.PEM
	out.CRL, e = m.crlLocked(id)
	return out, e
}
