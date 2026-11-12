package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Destination struct {
	URL      string `json:"url"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

func (d Destination) Validate() error {
	if d.URL == "" {
		return nil
	}
	u, err := url.Parse(d.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("Укажите адрес ClickHouse без пути, параметров и учётных данных")
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip.IsLoopback()) {
		return errors.New("Для ClickHouse нужен HTTPS или HTTP на loopback")
	}
	if !identifier.MatchString(d.Database) || len(d.User) > 128 || len(d.Password) > 1024 {
		return errors.New("Некорректное имя базы или учётные данные")
	}
	return nil
}

type ClickHouse struct {
	destination Destination
	client      *http.Client
}

func Connect(d Destination) *ClickHouse {
	return &ClickHouse{destination: d, client: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

const table = "gfw_traffic_v1"

const ddl = `CREATE TABLE IF NOT EXISTS gfw_traffic_v1 (
	event_id String, device String, boot String, namespace String, at_ms Int64,
	kind LowCardinality(String), flow_id String, zone UInt16, src String, dst String,
	sport UInt16, dport UInt16, reply_src String, reply_dst String, reply_sport UInt16, reply_dport UInt16,
	proto UInt8, nat Bool, bytes Nullable(UInt64), packets Nullable(UInt64),
	reply_bytes Nullable(UInt64), reply_packets Nullable(UInt64), rule String, revision Int64,
	action LowCardinality(String), direction LowCardinality(String), in_ifindex UInt32, out_ifindex UInt32
) ENGINE=ReplacingMergeTree
PARTITION BY toYYYYMM(toDateTime(intDiv(at_ms,1000)))
ORDER BY (at_ms,event_id)
TTL toDateTime(intDiv(at_ms,1000)) + toIntervalDay(if(kind='rule',90,30))`

func (c *ClickHouse) request(ctx context.Context, query string, data io.Reader, params url.Values) ([]byte, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("database", c.destination.Database)
	params.Set("query", query)
	params.Set("wait_end_of_query", "1")
	params.Set("output_format_json_quote_64bit_integers", "0")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.destination.URL, "/")+"/?"+params.Encode(), data)
	if err != nil {
		return nil, errors.New("Некорректный адрес ClickHouse")
	}
	if c.destination.User != "" || c.destination.Password != "" {
		req.SetBasicAuth(c.destination.User, c.destination.Password)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	response, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("Не удалось подключиться к ClickHouse")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("ClickHouse вернул HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		return nil, errors.New("Ответ ClickHouse неполный или слишком большой")
	}
	return body, nil
}

func (c *ClickHouse) Init(ctx context.Context) error {
	return c.execute(ctx, ddl, nil)
}

func (c *ClickHouse) execute(ctx context.Context, query string, data io.Reader) error {
	body, err := c.request(ctx, query, data, nil)
	if err == nil && len(bytes.TrimSpace(body)) != 0 {
		return errors.New("ClickHouse не подтвердил выполнение запроса")
	}
	return err
}

func (c *ClickHouse) Insert(ctx context.Context, batch Batch) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range batch.Events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return c.execute(ctx, "INSERT INTO "+table+" FORMAT JSONEachRow", &body)
}

func (c *ClickHouse) Search(ctx context.Context, input url.Values) ([]Event, error) {
	hours, err := strconv.Atoi(input.Get("hours"))
	if err != nil || hours < 1 || hours > 2160 {
		return nil, errors.New("Диапазон поиска должен быть от 1 до 2160 часов")
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	conditions := []string{"at_ms >= {since:Int64}"}
	params := url.Values{"param_since": {strconv.FormatInt(cutoff, 10)}, "max_execution_time": {"5"}}
	add := func(name, value, condition string) {
		conditions = append(conditions, condition)
		params.Set("param_"+name, value)
	}
	switch input.Get("kind") {
	case "":
	case "flow":
		conditions = append(conditions, "kind != 'rule'")
	case "rule":
		conditions = append(conditions, "kind = 'rule'")
	default:
		return nil, errors.New("Неизвестный вид события")
	}
	if value := input.Get("ip"); value != "" {
		prefix, e := netip.ParsePrefix(value)
		if e != nil {
			ip, e := netip.ParseAddr(value)
			if e != nil || ip.Zone() != "" {
				return nil, errors.New("Укажите IP или CIDR")
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		add("ip", prefix.Masked().String(), "(isIPAddressInRange(src,{ip:String}) OR isIPAddressInRange(dst,{ip:String}) OR isIPAddressInRange(reply_src,{ip:String}) OR isIPAddressInRange(reply_dst,{ip:String}))")
	}
	if value := input.Get("port"); value != "" {
		if p, e := strconv.ParseUint(value, 10, 16); e != nil || p == 0 {
			return nil, errors.New("Укажите порт от 1 до 65535")
		}
		add("port", value, "(sport={port:UInt16} OR dport={port:UInt16} OR reply_sport={port:UInt16} OR reply_dport={port:UInt16})")
	}
	if value := input.Get("proto"); value != "" {
		if _, e := strconv.ParseUint(value, 10, 8); e != nil {
			return nil, errors.New("Некорректный номер протокола")
		}
		add("proto", value, "proto = {proto:UInt8}")
	}
	for _, field := range []string{"rule", "action", "flow_id", "device"} {
		if value := input.Get(field); value != "" {
			if len(value) > 128 {
				return nil, errors.New("Слишком длинный фильтр")
			}
			add(field, value, field+" = {"+field+":String}")
		}
	}
	query := "SELECT * FROM " + table + " FINAL WHERE " + strings.Join(conditions, " AND ") + " ORDER BY at_ms DESC,event_id DESC LIMIT 250 FORMAT JSONEachRow"
	raw, err := c.request(ctx, query, nil, params)
	if err != nil {
		return nil, err
	}
	out := []Event{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var e Event
		err = dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("ClickHouse вернул некорректные события")
		}
		out = append(out, e)
	}
	return out, nil
}
