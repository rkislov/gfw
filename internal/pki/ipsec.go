package pki

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/ipsec"
)

// IPsecMaterial delivers only the local gateway's private key.
func (m *Manager) IPsecMaterial(t ipsec.Tunnel) (ipsec.Material, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ipsecMaterial(t)
}

func (m *Manager) ipsecMaterial(t ipsec.Tunnel) (ipsec.Material, error) {
	out := ipsec.Material{Tunnel: t}
	if err := ipsec.ValidateTunnel(t); err != nil {
		return out, err
	}
	own, err := m.get(t.CertificateID)
	if err != nil {
		return out, err
	}
	if t.Auth == nil || t.Auth.Certificate {
		peer, err := m.get(t.PeerCertificateID)
		if err != nil {
			return out, err
		}
		if peer.Kind != "local" || own.CAID != peer.CAID || peer.RevokedAt != nil || t.Auth != nil && peer.Usage != "client" {
			return out, errors.New("нужен действующий сертификат peer того же CA")
		}
		out.Peer = peer.PEM
	}
	if own.Kind != "local" || own.RevokedAt != nil || t.Auth != nil && own.Usage != "server" {
		return out, errors.New("выберите действующие сертификаты обоих шлюзов, выпущенные одним локальным CA")
	}
	root, err := m.get(own.CAID)
	if err != nil {
		return out, err
	}
	if root.Kind != "ca" {
		return out, errors.New("нужен локальный CA")
	}
	list, err := m.crlLocked(root.ID)
	if err != nil {
		return out, err
	}
	out.CAID, out.CA, out.CRL = root.ID, root.PEM, list
	out.Certificate, out.Key = own.PEM, own.Key
	return out, ipsec.ValidateMaterial(out)
}

// ExportIPsec packages the trust anchor and, when required, the named client's key.
func (m *Manager) ExportIPsec(t ipsec.Tunnel, username string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.Auth == nil || !identity.Username.MatchString(username) || t.Auth.Certificate && t.ClientUser != username {
		return nil, errors.New("профиль IKEv2 недоступен")
	}
	bundle, err := m.ipsecMaterial(t)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	write := func(path string, contents []byte) error {
		entry, err := z.Create(path)
		if err == nil {
			_, err = entry.Write(contents)
		}
		return err
	}
	local := "local"
	if t.Auth.Certificate {
		peer, err := m.get(t.PeerCertificateID)
		if err != nil {
			return nil, err
		}
		if _, err = validatePair(peer.PEM, peer.Key, m.now()); err != nil {
			return nil, err
		}
		for _, file := range []struct {
			name string
			data []byte
		}{{"x509/gfw-client.pem", peer.PEM}, {"private/gfw-client.pem", peer.Key}} {
			if err := write(file.name, file.data); err != nil {
				return nil, err
			}
		}
		local = fmt.Sprintf("local-cert {\n      auth = pubkey\n      id = @%s\n      certs = gfw-client.pem\n      round = 0\n    }\n    local-eap", username)
	}
	code := "REPLACE_WITH_PASSWORD"
	if t.Auth.TOTP {
		if t.Auth.Password == "" {
			code = "REPLACE_WITH_TOTP"
		} else {
			code = "REPLACE_WITH_PASSWORD_AND_TOTP"
		}
	}
	config := fmt.Sprintf(`connections {
  gfw-user {
    version = 2
    remote_addrs = %s
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-ecp256
    %s {
      auth = eap-gtc
      id = @%s
      eap_id = %s
      round = %d
    }
    remote {
      auth = pubkey
      id = %s
    }
    children {
      gfw {
        remote_ts = %s
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
secrets {
  eap-gfw {
    id = %s
    secret = "%s"
  }
}
`, t.PublicEndpoint, local, username, username, map[bool]int{true: 1, false: 0}[t.Auth.Certificate], ipsec.IKEIdentity(t.PublicEndpoint), strings.Join(t.LocalNetworks, ","), username, code)
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"swanctl.conf", []byte(config)},
		{"x509ca/gfw-ca.pem", bundle.CA},
		{"README.txt", []byte("IKEv2 / EAP-GTC (strongSwan). Используйте текущий пароль, пароль:код при 2FA или только код в режиме сертификат + TOTP.\nСкопируйте файлы в соответствующие каталоги swanctl на тестовом клиенте, подставьте секрет в закрытой копии, выполните swanctl --load-all и swanctl --initiate --child gfw.\nДля новой сессии с TOTP нужен свежий код. Не передавайте архив третьим лицам.\n")},
	} {
		if err := write(file.name, file.data); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
