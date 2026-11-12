package vpncred

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Vault struct {
	root string
	aead cipher.AEAD
}

func OpenVault(root string) (*Vault, error) {
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("VPN vault requires private directory")
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
			return nil, errors.New("VPN device key missing; restore vault backup")
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
			return nil, errors.New("invalid VPN device key")
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

func (v *Vault) Put(name string, value any) error {
	if name == "." || name == ".." || filepath.Base(name) != name || name == "device.key" {
		return errors.New("invalid vault entry name")
	}

	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw = v.aead.Seal(nonce, nonce, raw, []byte(name))
	f, e := os.CreateTemp(v.root, ".stage-")
	if e != nil {
		return e
	}
	path := f.Name()
	defer os.Remove(path)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(path, filepath.Join(v.root, name)); e != nil {
		return e
	}
	d, e := os.Open(v.root)
	if e != nil {
		return e
	}
	return errors.Join(d.Sync(), d.Close())
}
func (v *Vault) Get(name string, value any) error {
	if name == "." || name == ".." || filepath.Base(name) != name || name == "device.key" {
		return errors.New("invalid vault entry name")
	}

	path := filepath.Join(v.root, name)
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
		return errors.New("unsafe VPN vault entry")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	n := v.aead.NonceSize()
	if len(raw) < n {
		return errors.New("corrupt VPN vault entry")
	}
	raw, e = v.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if e != nil {
		return errors.New("cannot decrypt VPN vault; restore device key and backup")
	}
	return json.Unmarshal(raw, value)
}
