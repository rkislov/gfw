// Package metrics reads read-only system and interface counters on a Linux node.
package metrics

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var ErrUnsupported = errors.New("system metrics are available on Linux")

type CPU struct {
	Total uint64 `json:"total,string"`
	Idle  uint64 `json:"idle,string"`
}

type Interface struct {
	Name string `json:"name"`
	RX   uint64 `json:"rx_bytes,string"`
	TX   uint64 `json:"tx_bytes,string"`
}

type Sample struct {
	UptimeMS        int64       `json:"uptime_ms"`
	CPU             CPU         `json:"cpu"`
	MemoryTotal     uint64      `json:"memory_total"`
	MemoryAvailable uint64      `json:"memory_available"`
	Interfaces      []Interface `json:"interfaces"`
}

func Read() (Sample, error) {
	var sample Sample
	if runtime.GOOS != "linux" {
		return sample, ErrUnsupported
	}
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return sample, err
	}
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return sample, err
	}
	dev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return sample, err
	}
	uptime, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return sample, err
	}
	return parse(stat, mem, dev, uptime)
}

func parse(stat, mem, dev, uptime []byte) (Sample, error) {
	var sample Sample
	firstLine, _, _ := bytes.Cut(stat, []byte("\n"))
	fields := strings.Fields(string(firstLine))
	if len(fields) < 9 || fields[0] != "cpu" {
		return sample, errors.New("invalid aggregate CPU counters")
	}
	// Guest time is already included in user and nice.
	for i, field := range fields[1:9] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return sample, err
		}
		sample.CPU.Total += value
		if i == 3 || i == 4 { // idle and iowait
			sample.CPU.Idle += value
		}
	}

	var available bool
	for _, line := range strings.Split(string(mem), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" && fields[0] != "MemAvailable:" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return sample, err
		}
		if fields[0] == "MemTotal:" {
			sample.MemoryTotal = value * 1024
		} else {
			sample.MemoryAvailable = value * 1024
			available = true
		}
	}
	if !available || sample.MemoryTotal == 0 || sample.MemoryAvailable > sample.MemoryTotal {
		return sample, errors.New("invalid memory counters")
	}

	sample.Interfaces = []Interface{}
	scanner := bufio.NewScanner(bytes.NewReader(dev))
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.LastIndexByte(line, ':')
		if separator < 0 {
			continue // header
		}
		fields := strings.Fields(line[separator+1:])
		if len(fields) != 16 {
			return sample, errors.New("invalid interface counters")
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return sample, err
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return sample, err
		}
		sample.Interfaces = append(sample.Interfaces, Interface{
			Name: strings.TrimSpace(line[:separator]), RX: rx, TX: tx,
		})
	}
	if err := scanner.Err(); err != nil {
		return sample, err
	}
	fields = strings.Fields(string(uptime))
	if len(fields) != 2 {
		return sample, errors.New("invalid uptime")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || !(seconds >= 0 && seconds < 1e12) {
		return sample, errors.New("invalid uptime")
	}
	sample.UptimeMS = int64(seconds * 1000)
	return sample, nil
}
