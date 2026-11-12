// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

const MaxImport = 32 << 20

func ParseFeed(r io.Reader) ([]string, error) { return parseFeed(r, false) }

// The subscription provider may mix a small number of non-domain IoCs into
// domains.txt. Accept valid DNS names, but fail closed on empty/corrupt feeds.
func parseFeed(r io.Reader, mixed bool) ([]string, error) {
	br := bufio.NewReader(r)
	magic, _ := br.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, e := gzip.NewReader(br)
		if e != nil {
			return nil, e
		}
		defer gz.Close()
		br = bufio.NewReader(gz)
	}
	lr := &io.LimitedReader{R: br, N: MaxImport + 1}
	scan := bufio.NewScanner(lr)
	scan.Buffer(make([]byte, 4096), 1<<20)
	set := map[string]struct{}{}
	accepted, skipped := 0, 0
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		line = strings.SplitN(line, "#", 2)[0]
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			fields = fields[1:]
		} else if len(fields) != 1 {
			if mixed {
				skipped++
				continue
			}
			return nil, fmt.Errorf("unsupported feed line: %.100s", line)
		}
		for _, d := range fields {
			if strings.HasPrefix(d, "||") && strings.HasSuffix(d, "^") {
				d = strings.TrimSuffix(strings.TrimPrefix(d, "||"), "^")
			}
			d = strings.TrimSuffix(strings.ToLower(d), ".")
			if d == "localhost" || d == "localhost.localdomain" || d == "broadcasthost" {
				continue
			}
			if !validName(d) || !strings.Contains(d, ".") {
				if mixed {
					skipped++
					continue
				}
				return nil, fmt.Errorf("invalid feed domain: %.100s", d)
			}
			if _, err := netip.ParseAddr(d); err == nil {
				continue
			}
			accepted++
			set[d] = struct{}{}
			if len(set) > 1000000 {
				return nil, fmt.Errorf("feed exceeds 1 million domains")
			}
		}
	}
	if e := scan.Err(); e != nil {
		return nil, e
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("uncompressed feed exceeds 32 MiB")
	}
	if mixed && (len(set) == 0 || skipped*20 > accepted) {
		return nil, fmt.Errorf("subscription feed contains no DNS names or more than 5%% invalid entries")
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
func DownloadFeed(ctx context.Context, f Feed) ([]string, error) {
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("feed URL must use HTTP(S) without URL credentials")
	}
	if f.Authorization != "" && u.Scheme != "https" {
		return nil, fmt.Errorf("subscription credentials require HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return nil, err
	}
	if f.Authorization != "" {
		req.Header.Set("Authorization", feedAuthorization(u, f.Authorization))
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			return fmt.Errorf("unsupported redirect")
		}
		if f.Authorization != "" && (req.URL.Host != u.Host || req.URL.Scheme != "https") {
			return fmt.Errorf("authenticated feed cannot redirect to another origin")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("feed HTTP status %d", resp.StatusCode)
	}
	return parseFeed(io.LimitReader(resp.Body, MaxImport+1), strings.EqualFold(u.Hostname(), "feed.kislovs.ru"))
}
func ParseZone(r io.Reader, name string) ([]string, error) {
	name = canonical(name)
	if !validName(name) {
		return nil, fmt.Errorf("invalid zone name")
	}
	p := dns.NewZoneParser(io.LimitReader(r, MaxImport+1), name, "")
	p.SetIncludeAllowed(false)
	out := []string{}
	for rr, ok := p.Next(); ok; rr, ok = p.Next() {
		if len(out) >= 100000 {
			return nil, fmt.Errorf("zone exceeds 100000 records")
		}
		out = append(out, rr.String())
	}
	if err := p.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// feed.kislovs.ru subscription keys may be pasted without the HTTP scheme.
// Other providers retain their explicitly configured Authorization value.
func feedAuthorization(u *url.URL, value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(u.Hostname(), "feed.kislovs.ru") && strings.HasPrefix(value, "ff_") && !strings.ContainsAny(value, " \t\r\n") {
		return "Bearer " + value
	}
	return value
}
