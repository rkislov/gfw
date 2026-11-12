// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestFeedAuthorizationSchemes(t *testing.T) {
	for _, tc := range []struct{ host, value, want string }{
		{"feed.kislovs.ru", "ff_test-key", "Bearer ff_test-key"},
		{"FEED.KISLOVS.RU:443", " ff_test-key ", "Bearer ff_test-key"},
		{"feed.kislovs.ru", "Bearer ff_test-key", "Bearer ff_test-key"},
		{"other.example", "ff_test-key", "ff_test-key"},
		{"feed.kislovs.ru.attacker.example", "ff_test-key", "ff_test-key"},
		{"feed.kislovs.ru", "Basic dGVzdA==", "Basic dGVzdA=="},
	} {
		u, _ := url.Parse("https://" + tc.host + "/feeds/v1/domains.txt")
		if got := feedAuthorization(u, tc.value); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.host, got, tc.want)
		}
	}
}

func TestSubscriptionMixedIoCsAndCorruption(t *testing.T) {
	var good strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&good, "bad%d.example\n", i)
	}
	data := good.String() + "8e183523fc21ce8affec7e618908fa98\nnot-a-domain\nhttps://invalid.example/path\n"
	domains, err := parseFeed(strings.NewReader(data), true)
	if err != nil || len(domains) != 100 {
		t.Fatal("valid subscription rejected", len(domains), err)
	}
	if _, err := ParseFeed(strings.NewReader(data)); err == nil {
		t.Fatal("generic parser lost strict validation")
	}
	for _, bad := range []string{"", "<html>login required</html>", good.String() + strings.Repeat("not-a-domain\n", 6)} {
		if _, err := parseFeed(strings.NewReader(bad), true); err == nil {
			t.Fatal("corrupt subscription accepted")
		}
	}
}
