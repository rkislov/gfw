package feed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// Filter pins a downloaded list and keeps locally entered exceptions separate.
type Filter struct {
	SHA256     string   `json:"sha256"`
	Values     []string `json:"values"`
	Exceptions []string `json:"exceptions,omitempty"`
}

const MaxFilterBytes = 1 << 20
const MaxExceptions = 256

func CanonicalIP(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return "", ErrInvalidData
		}
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4In6() {
		return "", ErrInvalidData
	}
	return prefix.Masked().String(), nil
}

func CanonicalDomain(value string) (string, error) {
	value, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(value), "."))
	if err != nil || len(value) > 253 || !strings.Contains(value, ".") {
		return "", ErrInvalidData
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", ErrInvalidData
		}
	}
	return value, nil
}

func (f *Filter) Validate(kind string) error {
	if f == nil {
		return nil
	}
	hash, err := hex.DecodeString(f.SHA256)
	if err != nil || len(hash) != 32 || len(f.Values) == 0 || len(f.Exceptions) > MaxExceptions {
		return errors.New("Security Feed: нужен SHA-256 снимка, непустой список и не более 256 исключений")
	}
	normalize := CanonicalDomain
	if kind == "ip" {
		normalize = CanonicalIP
	}
	var size int
	for _, values := range [][]string{f.Values, f.Exceptions} {
		for _, v := range values {
			size += len(v) + 4
			if size > MaxFilterBytes {
				return errors.New("Security Feed: список превышает лимит развёртывания 1 МиБ")
			}
			norm, err := normalize(v)
			if err != nil || v != norm || kind == "ip" && strings.HasSuffix(v, "/0") {
				return fmt.Errorf("Security Feed: некорректная запись %q", v)
			}
		}
	}
	return nil
}

func NewFilter(kind, sha string, normalized []byte, exceptions []string) (*Filter, error) {
	if len(normalized) > MaxFilterBytes || len(exceptions) > MaxExceptions {
		return nil, errors.New("Security Feed: список превышает лимит 1 МиБ или 256 исключений")
	}
	normalize := CanonicalDomain
	if kind == "ip" {
		normalize = CanonicalIP
	}
	excluded := make([]string, 0, len(exceptions))
	for _, value := range exceptions {
		value = strings.TrimSpace(value)
		norm, err := normalize(value)
		if err != nil {
			return nil, fmt.Errorf("Security Feed: неверное исключение %q", value)
		}
		excluded = append(excluded, norm)
	}
	slices.Sort(excluded)
	f := &Filter{
		SHA256:     sha,
		Values:     strings.Split(strings.TrimSuffix(string(normalized), "\n"), "\n"),
		Exceptions: slices.Compact(excluded),
	}
	return f, f.Validate(kind)
}

type FilterSummary struct {
	SHA256     string `json:"sha256"`
	Count      int    `json:"count"`
	Exceptions int    `json:"exceptions"`
}

func (f *Filter) Summary() *FilterSummary {
	if f == nil {
		return nil
	}
	return &FilterSummary{SHA256: f.SHA256, Count: len(f.Values), Exceptions: len(f.Exceptions)}
}
