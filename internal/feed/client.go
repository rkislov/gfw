package feed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

const Origin = "https://feed.kislovs.ru"

type Entry struct {
	Name       string `json:"name"`
	Count      int    `json:"count"`
	SHA256     string `json:"sha256"`
	Source     string `json:"source,omitempty"`
	Raw        []byte `json:"-"`
	Normalized []byte `json:"-"`
}

type Client struct {
	origin string
	http   *http.Client
}

func NewClient() *Client {
	return newClient(Origin, nil)
}

func newClient(origin string, transport http.RoundTripper) *Client {
	return &Client{origin: origin, http: &http.Client{
		Transport:     transport,
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) fetch(ctx context.Context, key, name string, limit int64) (Entry, error) {
	e := Entry{Name: name}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/feeds/v1/"+name, nil)
	if err != nil {
		return e, errors.New("не удалось создать запрос Security Feed")
	}
	req.Header.Set("X-Api-Key", key)
	resp, err := c.http.Do(req)
	if err != nil {
		return e, fmt.Errorf("%s: ошибка соединения HTTPS (сеть, сертификат или тайм-аут)", name)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return e, errors.New("Security Feed отклонил ключ или подписку")
	case http.StatusServiceUnavailable:
		return e, fmt.Errorf("%s: данные временно недоступны", name)
	default:
		return e, fmt.Errorf("%s: Security Feed вернул HTTP %d", name, resp.StatusCode)
	}
	e.Raw, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(e.Raw)) > limit {
		return e, fmt.Errorf("%s: неполный ответ или превышен лимит размера", name)
	}
	sum := sha256.Sum256(e.Raw)
	e.SHA256 = hex.EncodeToString(sum[:])
	// The service labels its projections with a short source identifier.
	if source := resp.Header.Get("X-Feed-Source"); sourcePattern.MatchString(source) && !strings.Contains(source, key) {
		e.Source = source
	}
	return e, nil
}

var sourcePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var ErrInvalidData = errors.New("некорректный или пустой набор")

func (c *Client) Catalog(ctx context.Context, key string) (Entry, error) {
	e, err := c.fetch(ctx, key, "catalog.json", 256<<10)
	if err != nil {
		return e, err
	}
	var catalog struct {
		Product string
		Domains string
		IOC     string `json:"ioc_json"`
	}
	if json.Unmarshal(e.Raw, &catalog) != nil || catalog.Product != "Security Feed" ||
		catalog.Domains != "/feeds/v1/domains.txt" || catalog.IOC != "/feeds/v1/iocs.json" {
		return Entry{}, fmt.Errorf("catalog.json: %w", ErrInvalidData)
	}
	return e, nil
}

func (c *Client) Download(ctx context.Context, key string) ([]Entry, error) {
	catalog, err := c.Catalog(ctx, key)
	if err != nil {
		return nil, err
	}
	entries := []Entry{catalog}
	for _, spec := range []struct {
		name  string
		limit int64
	}{
		{"ips.txt", 12 << 20}, {"domains.txt", 12 << 20}, {"iocs.json", 96 << 20},
	} {
		entry, err := c.fetch(ctx, key, spec.name, spec.limit)
		if err != nil {
			return nil, err
		}
		if spec.name == "iocs.json" {
			entry.Count, err = countIOCs(entry.Raw)
		} else {
			entry.Normalized, entry.Count, err = normalizeList(entry.Raw, spec.name == "ips.txt")
		}
		if err != nil || entry.Count == 0 {
			return nil, fmt.Errorf("%s: %w", spec.name, ErrInvalidData)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func normalizeList(raw []byte, ip bool) ([]byte, int, error) {
	unique := map[string]struct{}{}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	for lines.Scan() {
		value := strings.TrimSpace(lines.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		normalize := CanonicalDomain
		if ip {
			normalize = CanonicalIP
		}
		value, err := normalize(value)
		if err != nil {
			return nil, 0, err
		}
		unique[value] = struct{}{}
	}
	if err := lines.Err(); err != nil {
		return nil, 0, err
	}
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	slices.Sort(values)
	return []byte(strings.Join(values, "\n") + "\n"), len(values), nil
}

func countIOCs(raw []byte) (int, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if start, err := d.Token(); err != nil || start != json.Delim('[') {
		return 0, ErrInvalidData
	}
	var count int
	for d.More() {
		var entry struct{ Type, Value, Source string }
		if err := d.Decode(&entry); err != nil || strings.TrimSpace(entry.Type) == "" ||
			strings.TrimSpace(entry.Value) == "" || strings.TrimSpace(entry.Source) == "" {
			return 0, ErrInvalidData
		}
		count++
	}
	if end, err := d.Token(); err != nil || end != json.Delim(']') {
		return 0, ErrInvalidData
	}
	if _, err := d.Token(); err != io.EOF {
		return 0, ErrInvalidData
	}
	return count, nil
}
