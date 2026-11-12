// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"strings"
	"testing"
	"time"
)

func TestConfigAndIANA(t *testing.T) {
	c := DefaultConfig()
	zero := uint16(0)
	c.MaxNSEC3Iterations = &zero
	normalized, err := Normalize(c)
	if err != nil || *normalized.MaxNSEC3Iterations != 0 {
		t.Fatal("explicit zero lost", err)
	}
	normalized.TrustAnchors[0] = "changed"
	if c.TrustAnchors[0] == "changed" {
		t.Fatal("mutable anchors")
	}
	xml := `<TrustAnchor><Zone>.</Zone><KeyDigest validFrom="2020-01-01T00:00:00Z"><KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest></KeyDigest></TrustAnchor>`
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	anchors, err := parseIANA(strings.NewReader(xml), now)
	if err != nil || len(anchors) != 1 {
		t.Fatal(anchors, err)
	}
	for _, bad := range []string{strings.Replace(xml, "<Zone>.</Zone>", "<Zone>evil.</Zone>", 1), strings.Replace(xml, "2020-01-01", "2030-01-01", 1), strings.Replace(xml, "validFrom=", `validUntil="2021-01-01T00:00:00Z" validFrom=`, 1), strings.Replace(xml, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "00", 1)} {
		if _, err := parseIANA(strings.NewReader(bad), now); err == nil {
			t.Fatal("invalid IANA accepted")
		}
	}
}
