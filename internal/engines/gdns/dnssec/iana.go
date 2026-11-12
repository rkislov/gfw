// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package dnssec

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const IANAURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// FetchIANA returns an authenticated-HTTPS snapshot for an administrator to
// review and save. It never silently changes trust or disables TLS checks.
func FetchIANA(ctx context.Context) ([]string, error) {
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || r.URL.Scheme != "https" || r.URL.Host != "data.iana.org" {
			return fmt.Errorf("unexpected IANA redirect")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", IANAURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("IANA HTTP %d", resp.StatusCode)
	}
	return parseIANA(io.LimitReader(resp.Body, 1<<20), time.Now())
}
func parseIANA(r io.Reader, now time.Time) ([]string, error) {
	var root struct {
		Zone string `xml:"Zone"`
		Keys []struct {
			From       string `xml:"validFrom,attr"`
			Until      string `xml:"validUntil,attr"`
			Tag        uint16 `xml:"KeyTag"`
			Algorithm  uint8  `xml:"Algorithm"`
			DigestType uint8  `xml:"DigestType"`
			Digest     string `xml:"Digest"`
		} `xml:"KeyDigest"`
	}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, err
	}
	if root.Zone != "." {
		return nil, fmt.Errorf("IANA trust anchor zone must be root")
	}
	anchors := []string{}
	for _, key := range root.Keys {
		from, err := time.Parse(time.RFC3339, key.From)
		if err != nil {
			return nil, err
		}
		if now.Before(from) {
			continue
		}
		if key.Until != "" {
			until, err := time.Parse(time.RFC3339, key.Until)
			if err != nil {
				return nil, err
			}
			if !now.Before(until) {
				continue
			}
		}
		anchors = append(anchors, ". 3600 IN DS "+strconv.Itoa(int(key.Tag))+" "+strconv.Itoa(int(key.Algorithm))+" "+strconv.Itoa(int(key.DigestType))+" "+key.Digest)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("IANA returned no currently valid root anchors")
	}
	c := DefaultConfig()
	c.TrustAnchors = anchors
	normalized, err := Normalize(c)
	if err != nil {
		return nil, err
	}
	return normalized.TrustAnchors, nil
}
