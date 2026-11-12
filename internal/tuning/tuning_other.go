//go:build !linux

package tuning

import "errors"

func Execute(action, token string) (Plan, error) {
	return Plan{}, errors.New("настройка sysctl доступна на Linux-агенте")
}
