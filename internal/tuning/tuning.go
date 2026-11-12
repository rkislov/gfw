package tuning

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

type Setting struct {
	Key     string `json:"key"`
	Current uint64 `json:"current"`
	Target  uint64 `json:"target"`
}

type Plan struct {
	MemoryMiB uint64    `json:"memory_mib"`
	CPUs      int       `json:"cpus"`
	Settings  []Setting `json:"settings"`
	Skipped   []string  `json:"skipped"`
	Managed   bool      `json:"managed"`
	Token     string    `json:"token,omitempty"`
}

var keys = []string{"net.core.somaxconn", "net.core.netdev_max_backlog", "net.netfilter.nf_conntrack_max"}

func recommendation(memory uint64, cpus int) []uint64 {
	// The conntrack budget assumes 1 KiB per entry and allows up to 1/32 of RAM.
	return []uint64{
		min(16384, max(1024, uint64(cpus)*512)),
		min(16384, max(1000, min(memory*2, uint64(cpus)*1024))),
		min(1048576, memory*32),
	}
}

func sign(p Plan) string {
	p.Token = ""
	b, _ := json.Marshal(p)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
