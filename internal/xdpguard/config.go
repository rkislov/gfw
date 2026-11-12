// Package xdpguard manages early IP filtering on WAN interfaces.
package xdpguard

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/netconfig"
)

type Config struct {
	Interfaces []string     `json:"interfaces"`
	Mode       string       `json:"mode"`
	Match      string       `json:"match"`
	Block      []string     `json:"block"`
	Feed       *feed.Filter `json:"feed,omitempty"`
}

func (c Config) Normalize() (Config, error) {
	if len(c.Interfaces) == 0 {
		if len(c.Block) > 0 || c.Feed != nil {
			return Config{}, errors.New("выберите WAN-интерфейс или отключите профиль целиком")
		}
		return Config{}, nil
	}
	if len(c.Interfaces) > 8 || len(c.Block) > 4096 {
		return Config{}, errors.New("допускается до восьми интерфейсов и 4096 ручных блокировок")
	}
	if c.Mode != "native" && c.Mode != "generic" {
		return Config{}, errors.New("выберите режим XDP в драйвере или generic")
	}
	if c.Match != "source" && c.Match != "destination" && c.Match != "both" {
		return Config{}, errors.New("выберите поля адресов для проверки")
	}
	c.Interfaces = slices.Clone(c.Interfaces)
	for _, name := range c.Interfaces {
		if !netconfig.Name.MatchString(name) {
			return Config{}, fmt.Errorf("недопустимый интерфейс %q", name)
		}
	}
	slices.Sort(c.Interfaces)
	c.Interfaces = slices.Compact(c.Interfaces)
	block := make([]string, 0, len(c.Block))
	for _, s := range c.Block {
		p, err := feed.CanonicalIP(strings.TrimSpace(s))
		if err != nil || strings.HasSuffix(p, "/0") {
			return Config{}, fmt.Errorf("недопустимый IP или CIDR %q", s)
		}
		block = append(block, p)
	}
	slices.Sort(block)
	c.Block = slices.Compact(block)
	if err := c.Feed.Validate("ip"); err != nil {
		return Config{}, err
	}
	if len(c.Block) == 0 && c.Feed == nil {
		return Config{}, errors.New("добавьте IP/CIDR или выберите снимок Security Feed")
	}
	return c, nil
}

type Profile struct {
	Interfaces []string            `json:"interfaces"`
	Mode       string              `json:"mode"`
	Match      string              `json:"match"`
	Block      []string            `json:"block"`
	Feed       *feed.FilterSummary `json:"feed,omitempty"`
	Exceptions []string            `json:"exceptions,omitempty"`
}

func (c Config) Profile() Profile {
	p := Profile{Interfaces: c.Interfaces, Mode: c.Mode, Match: c.Match, Block: c.Block, Feed: c.Feed.Summary()}
	if c.Feed != nil {
		p.Exceptions = c.Feed.Exceptions
	}
	return p
}

type Counters struct {
	Passed      uint64 `json:"passed"`
	PassedBytes uint64 `json:"passed_bytes"`
	ManualDrops uint64 `json:"manual_drops"`
	ManualBytes uint64 `json:"manual_bytes"`
	FeedDrops   uint64 `json:"feed_drops"`
	FeedBytes   uint64 `json:"feed_bytes"`
}

type Port struct {
	Name    string `json:"name"`
	IfIndex int    `json:"ifindex"`
	Counters
}

type Backend interface {
	Check(Config, string) error
	Activate(Config, string) error
	Verify(Config, string) error
	Ports() ([]Port, error)
	Deactivate() error
}
