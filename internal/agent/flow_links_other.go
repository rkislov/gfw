//go:build !linux

package agent

import "errors"

func routedFlowPorts() (map[string]bool, error) {
	return nil, errors.New("ускорение транзита требует Linux")
}
