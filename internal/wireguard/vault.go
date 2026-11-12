package wireguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
	"path/filepath"
	"strings"
)

type KeyInfo struct {
	Ref       string `json:"ref"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key,omitempty"`
}
type Vault struct {
	root string
	aead cipher.AEAD
}

func NewID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func OpenVault(root string) (*Vault, error) {
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("WireGuard vault requires private directory")
	}
	path := filepath.Join(root, "device.key")
	info, e = os.Lstat(path)
	var master []byte
	if errors.Is(e, os.ErrNotExist) {
		entries, e := os.ReadDir(root)
		if e != nil {
			return nil, e
		}
		if len(entries) != 0 {
			return nil, errors.New("WireGuard device key missing; restore vault backup")
		}
		master = make([]byte, 32)
		if _, e = rand.Read(master); e != nil {
			return nil, e
		}
		if e = writePrivate(path, master); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	} else {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
			return nil, errors.New("invalid WireGuard device key")
		}
		master, e = os.ReadFile(path)
		if e != nil {
			return nil, e
		}
	}
	block, e := aes.NewCipher(master)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	return &Vault{root: root, aead: aead}, e
}
func writePrivate(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	return errors.Join(dir.Sync(), dir.Close())
}
func (v *Vault) Generate(kind string) (KeyInfo, error) {
	if kind != "tunnel" && kind != "client" && kind != "psk" {
		return KeyInfo{}, errors.New("тип ключа tunnel, client или psk")
	}
	var key wgtypes.Key
	var e error
	if kind != "psk" {
		key, e = wgtypes.GeneratePrivateKey()
	} else {
		key, e = wgtypes.GenerateKey()
	}
	if e != nil {
		return KeyInfo{}, e
	}
	ref := NewID()
	nonce := make([]byte, v.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return KeyInfo{}, e
	}
	raw := append([]byte(kind+":"), key[:]...)
	secret := v.aead.Seal(nonce, nonce, raw, []byte(ref))
	if e = writePrivate(filepath.Join(v.root, ref+".key"), secret); e != nil {
		return KeyInfo{}, e
	}
	out := KeyInfo{Ref: ref, Kind: kind}
	if kind != "psk" {
		out.PublicKey = key.PublicKey().String()
	}
	return out, nil
}
func (v *Vault) Key(ref, kind string) (wgtypes.Key, error) {
	var key wgtypes.Key
	if !IDPattern.MatchString(ref) {
		return key, errors.New("неверная ссылка на ключ")
	}
	path := filepath.Join(v.root, ref+".key")
	info, e := os.Lstat(path)
	if e != nil {
		return key, errors.New("ключ WireGuard не найден")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256 {
		return key, errors.New("небезопасный файл ключа WireGuard")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return key, e
	}
	n := v.aead.NonceSize()
	if len(raw) < n {
		return key, errors.New("повреждён ключ WireGuard")
	}
	plain, e := v.aead.Open(nil, raw[:n], raw[n:], []byte(ref))
	if e != nil {
		return key, errors.New("не удалось расшифровать ключ WireGuard")
	}
	prefix := kind + ":"
	if !strings.HasPrefix(string(plain), prefix) {
		return key, errors.New("неверный тип ключа WireGuard")
	}
	return wgtypes.NewKey(plain[len(prefix):])
}
func (v *Vault) Validate(c Config) error {
	for _, t := range c.Tunnels {
		k, e := v.Key(t.KeyRef, "tunnel")
		if e != nil {
			return e
		}
		if k.PublicKey().String() != t.PublicKey {
			return errors.New("публичный ключ туннеля не соответствует ссылке")
		}
		for _, p := range t.Peers {
			if p.KeyRef != "" {
				k, e := v.Key(p.KeyRef, "client")
				if e != nil {
					return e
				}
				if k.PublicKey().String() != p.PublicKey {
					return errors.New("публичный ключ клиента не соответствует ссылке")
				}
			}
			if p.PSKRef != "" {
				if _, e := v.Key(p.PSKRef, "psk"); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (v *Vault) ClientProfile(c Config, tunnelID, peerID string) (string, error) {
	if e := Validate(c); e != nil {
		return "", e
	}
	if e := v.Validate(c); e != nil {
		return "", e
	}
	for _, t := range c.Tunnels {
		if t.ID != tunnelID {
			continue
		}
		for _, p := range t.Peers {
			if p.ID != peerID {
				continue
			}
			if p.KeyRef == "" || t.ClientEndpoint == "" || len(p.ClientAddresses) == 0 || len(p.ClientRoutes) == 0 {
				return "", errors.New("для экспорта нужны ключ клиента, внешний endpoint, адреса и маршруты клиента")
			}
			k, e := v.Key(p.KeyRef, "client")
			if e != nil {
				return "", e
			}
			s := "[Interface]\nPrivateKey = " + k.String() + "\nAddress = " + strings.Join(p.ClientAddresses, ", ") + "\n"
			if len(p.ClientDNS) > 0 {
				s += "DNS = " + strings.Join(p.ClientDNS, ", ") + "\n"
			}
			s += "\n[Peer]\nPublicKey = " + t.PublicKey + "\nEndpoint = " + t.ClientEndpoint + "\nAllowedIPs = " + strings.Join(p.ClientRoutes, ", ") + "\n"
			if p.PSKRef != "" {
				k, e := v.Key(p.PSKRef, "psk")
				if e != nil {
					return "", e
				}
				s += "PresharedKey = " + k.String() + "\n"
			}
			if p.Keepalive > 0 {
				s += fmt.Sprintf("PersistentKeepalive = %d\n", p.Keepalive)
			}
			return s, nil
		}
	}
	return "", errors.New("туннель или клиент не найден")
}
