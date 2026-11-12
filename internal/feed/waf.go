package feed

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
)

type WAFMeta struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Title   string `json:"title"`
	SHA256  string `json:"sha256"`
}

var wafSegment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,79}$`)

func (c *Client) WAFCatalog(ctx context.Context, key string) ([]WAFMeta, error) {
	entry, err := c.fetch(ctx, key, "waf/catalog.json", 256<<10)
	if err != nil {
		return nil, err
	}
	var result struct {
		Format string
		Packs  []WAFMeta
	}
	if json.Unmarshal(entry.Raw, &result) != nil || result.Format != "security-feed-waf-catalog-v1" {
		return nil, ErrInvalidData
	}
	return result.Packs, nil
}

func (c *Client) WAFPack(ctx context.Context, key, id, version, sha string) ([]byte, error) {
	if !wafSegment.MatchString(id) || !wafSegment.MatchString(version) || !ValidHash("sha256", sha) {
		return nil, ErrInvalidData
	}
	entry, err := c.fetch(ctx, key, "waf/packs/"+id+"/"+version+".json", 512<<10)
	if err != nil {
		return nil, err
	}
	if entry.SHA256 != sha {
		return nil, errors.New("SHA-256 набора WAF не совпадает с каталогом")
	}
	return entry.Raw, nil
}
