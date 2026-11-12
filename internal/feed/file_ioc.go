package feed

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const MaxScanFile = 16 << 20

type FileIndicator struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Source    string `json:"source"`
	Threat    string `json:"threat,omitempty"`
}

func HashSize(algorithm string) int {
	switch algorithm {
	case "md5":
		return 32
	case "sha1":
		return 40
	case "sha256":
		return 64
	}
	return 0
}

func ValidHash(algorithm, value string) bool {
	if len(value) == 0 || len(value) != HashSize(algorithm) || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func FileDigests(r io.Reader) (map[string]string, int64, error) {
	md, s1, s256 := md5.New(), sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(md, s1, s256), r)
	if err != nil {
		return nil, n, err
	}
	return map[string]string{"md5": hex.EncodeToString(md.Sum(nil)), "sha1": hex.EncodeToString(s1.Sum(nil)), "sha256": hex.EncodeToString(s256.Sum(nil))}, n, nil
}

func VisitFileIndicators(ctx context.Context, raw []byte, visit func(FileIndicator) error) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if start, err := dec.Token(); err != nil || start != json.Delim('[') {
		return ErrInvalidData
	}
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var item struct{ Type, Value, Source, Threat string }
		if err := dec.Decode(&item); err != nil {
			return ErrInvalidData
		}
		value := strings.ToLower(strings.TrimSpace(item.Value))
		kind := strings.ToLower(strings.TrimSpace(item.Type))
		algorithm, known := strings.CutSuffix(kind, "_hash")
		if !known && kind == "hash" {
			switch len(value) {
			case 32:
				algorithm = "md5"
			case 40:
				algorithm = "sha1"
			case 64:
				algorithm = "sha256"
			}
		}
		if ValidHash(algorithm, value) {
			if err := visit(FileIndicator{algorithm, value, item.Source, item.Threat}); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return ErrInvalidData
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidData
	}
	return nil
}
