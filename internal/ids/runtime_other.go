//go:build !linux

package ids

import "errors"

func NewRuntime(_, _, _ string, _, _ uint32) (Backend, error) {
	return nil, errors.New("Suricata IDS requires Linux")
}
