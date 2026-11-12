package openvpn

import "github.com/rkislov/gfw/internal/vpncred"

type Vault struct {
	*vpncred.Vault
	root string
}

func OpenVault(root string) (*Vault, error) {
	v, e := vpncred.OpenVault(root)
	if e != nil {
		return nil, e
	}
	return &Vault{Vault: v, root: root}, nil
}
func (v *Vault) put(name string, b any) error { return v.Put(name, b) }
func (v *Vault) Material(i Instance) (Material, error) {
	var b Material
	e := v.Get(Ref(i)+".bundle", &b)
	return b, e
}
