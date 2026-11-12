package capture

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type source interface {
	header() (uint32, layers.LinkType, error)
	next() ([]byte, gopacket.CaptureInfo, error)
	stop()
	close() (*uint64, error)
}
