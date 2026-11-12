//go:build !linux

package capture

import "errors"

func openSource(_ string, _ Config, _ string) (source, string, string, error) {
	return nil, "", "", errors.New("захват требует Linux-агента")
}
func validateBinary(_ string) error {
	return errors.New("захват требует Linux-агента")
}
func spaceAvailable(_ string, _ int64) error {
	return errors.New("захват требует Linux-агента")
}
