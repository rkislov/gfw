package identity

import (
	"errors"
	"regexp"
	"strings"
)

var Username = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
var Grant = regexp.MustCompile(`^(openvpn|ipsec):[a-zA-Z0-9_-]{1,64}$|^wireguard:[a-zA-Z0-9_-]{1,64}:[a-zA-Z0-9_-]{1,64}$`)

// Method describes the factors required by a managed VPN listener.
type Method struct {
	Password    string `json:"password"`
	Certificate bool   `json:"certificate"`
	TOTP        bool   `json:"totp"`
}

func (m Method) Validate() error {
	switch m.Password {
	case "local", "ldap", "radius", "either":
	case "":
		if !m.Certificate {
			return errors.New("выберите пароль или сертификат")
		}
	default:
		return errors.New("неизвестный источник пароля")
	}
	return nil
}

func (m Method) Credentials() bool { return m.Password != "" || m.TOTP }

type User struct {
	Name     string   `json:"name"`
	Source   string   `json:"source"`
	Role     string   `json:"role"`
	Disabled bool     `json:"disabled"`
	TOTP     bool     `json:"totp"`
	Grants   []string `json:"grants"`
	Revision int64    `json:"revision"`
}

func (u User) HasGrant(grant string) bool {
	for _, g := range u.Grants {
		if g == grant {
			return true
		}
	}
	return false
}

func (u User) Validate() error {
	if !Username.MatchString(u.Name) || (u.Source != "local" && u.Source != "ldap" && u.Source != "radius") ||
		(u.Role != "admin" && u.Role != "user") || len(u.Grants) > 128 {
		return errors.New("проверьте логин, источник, роль и число назначений")
	}
	for _, g := range u.Grants {
		if !Grant.MatchString(g) {
			return errors.New("некорректное назначение " + g)
		}
	}
	return nil
}

func SplitCode(secret string, required bool) (string, string) {
	if !required {
		return secret, ""
	}
	pass, code, ok := strings.Cut(secret, ":")
	// The password may itself contain colons.
	if ok {
		last := strings.LastIndexByte(secret, ':')
		return secret[:last], secret[last+1:]
	}
	return pass, code
}
