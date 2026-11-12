package netconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type RuntimeLink struct {
	IPv6Sysctls map[string]string `json:"ipv6_sysctls,omitempty"`
	Link        Link              `json:"link"`
	Master      string            `json:"master"`
	MAC         string            `json:"mac"`
	Dynamic     bool              `json:"dynamic"`
	Tentative   bool              `json:"tentative"`
}
type RuntimeRoute struct {
	Route    Route  `json:"route"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Scope    string `json:"scope"`
	Onlink   bool   `json:"onlink"`
}
type Snapshot struct {
	Netplan   *NetplanSnapshot     `json:"netplan,omitempty"`
	Scope     []string             `json:"scope"`
	Links     []RuntimeLink        `json:"links"`
	Routes    []RuntimeRoute       `json:"routes"`
	Files     map[string]Directory `json:"files"`
	Protected []string             `json:"protected"`
}
type Plan struct {
	Backend   string                       `json:"backend,omitempty"`
	Files     map[string]map[string]string `json:"files"`
	Actions   []string                     `json:"actions"`
	Protected []string                     `json:"protected"`
	CanApply  bool                         `json:"can_apply"`
	Warnings  []string                     `json:"warnings"`
}
type Backend interface {
	Prepare(Config, Config) (Snapshot, Plan, error)
	Activate(Config, Config) error
	Restore(Snapshot) error
	Verify(Config) error
}
type Linux struct {
	ctx  context.Context
	IP   string
	Root string
	LAN  string
}
type output struct{ bytes.Buffer }

func (b *output) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("ip output too large")
	}
	return b.Buffer.Write(p)
}
func (l Linux) run(args ...string) ([]byte, error) {
	parent := l.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, l.IP, args...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	out, stderr := &output{}, &output{}
	c.Stdout = out
	c.Stderr = stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("ip %v: %w: %s", args, err, stderr.String())
	}
	return out.Bytes(), nil
}
func (l Linux) cmd(args ...string) error { _, err := l.run(args...); return err }
func textValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	}
	return ""
}
func (l Linux) live() (map[string]RuntimeLink, []RuntimeRoute, error) {
	raw, err := l.run("-j", "-d", "link", "show")
	if err != nil {
		return nil, nil, err
	}
	var links []struct {
		Index      int      `json:"ifindex"`
		Name       string   `json:"ifname"`
		MTU        int      `json:"mtu"`
		MAC        string   `json:"address"`
		Flags      []string `json:"flags"`
		Master     string   `json:"master"`
		Parent     int      `json:"link_index"`
		ParentName string   `json:"link"`
		Info       struct {
			Kind string         `json:"info_kind"`
			Data map[string]any `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err = json.Unmarshal(raw, &links); err != nil {
		return nil, nil, err
	}
	names := map[int]string{}
	for _, a := range links {
		names[a.Index] = a.Name
	}
	out := map[string]RuntimeLink{}
	for _, a := range links {
		typ := a.Info.Kind
		if typ == "" || typ == "veth" {
			typ = "physical"
		}
		r := RuntimeLink{Link: Link{Name: a.Name, Type: typ, MTU: a.MTU, Addresses: []string{}, Members: []string{}}, Master: a.Master, MAC: a.MAC}
		for _, f := range a.Flags {
			if f == "UP" {
				r.Link.Up = true
			}
		}
		if typ == "vlan" {
			r.Link.Parent = a.ParentName
			if r.Link.Parent == "" {
				r.Link.Parent = names[a.Parent]
			}
			r.Link.VLAN, _ = strconv.Atoi(textValue(a.Info.Data["id"]))
		}
		if typ == "bond" {
			r.Link.BondMode = textValue(a.Info.Data["mode"])
		}
		out[a.Name] = r
	}
	for n, r := range out {
		r.IPv6Sysctls = map[string]string{}
		for _, key := range []string{"accept_ra", "autoconf"} {
			b, e := os.ReadFile("/proc/sys/net/ipv6/conf/" + n + "/" + key)
			if e == nil {
				r.IPv6Sysctls[key] = strings.TrimSpace(string(b))
			}
		}
		out[n] = r
	}
	for n, r := range out {
		if parent, ok := out[r.Master]; ok {
			parent.Link.Members = append(parent.Link.Members, n)
			out[r.Master] = parent
		}
	}
	raw, err = l.run("-j", "address", "show")
	if err != nil {
		return nil, nil, err
	}
	var addresses []struct {
		Name string `json:"ifname"`
		Addr []struct {
			Local     string `json:"local"`
			Prefix    int    `json:"prefixlen"`
			Scope     string `json:"scope"`
			Dynamic   bool   `json:"dynamic"`
			Temporary bool   `json:"temporary"`
			Tentative bool   `json:"tentative"`
			DADFailed bool   `json:"dadfailed"`
		} `json:"addr_info"`
	}
	if err = json.Unmarshal(raw, &addresses); err != nil {
		return nil, nil, err
	}
	for _, a := range addresses {
		r := out[a.Name]
		for _, ip := range a.Addr {
			if ip.Scope == "global" {
				r.Link.Addresses = append(r.Link.Addresses, fmt.Sprintf("%s/%d", ip.Local, ip.Prefix))
				r.Dynamic = r.Dynamic || ip.Dynamic || ip.Temporary
				r.Tentative = r.Tentative || ip.Tentative || ip.DADFailed
			}
		}
		out[a.Name] = r
	}
	routes := []RuntimeRoute{}
	for _, family := range []string{"-4", "-6"} {
		raw, err = l.run("-j", family, "route", "show", "table", "main")
		if err != nil {
			return nil, nil, err
		}
		var rows []struct {
			Dst       string          `json:"dst"`
			Gateway   string          `json:"gateway"`
			Dev       string          `json:"dev"`
			Metric    int             `json:"metric"`
			Protocol  any             `json:"protocol"`
			Source    string          `json:"prefsrc"`
			Scope     string          `json:"scope"`
			Flags     []string        `json:"flags"`
			Type      string          `json:"type"`
			Multipath json.RawMessage `json:"nexthops"`
		}
		if err = json.Unmarshal(raw, &rows); err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			if textValue(r.Protocol) == "kernel" {
				continue
			}
			dst := r.Dst
			if dst == "default" {
				dst = "0.0.0.0/0"
				if family == "-6" {
					dst = "::/0"
				}
			}
			if !strings.Contains(dst, "/") {
				if family == "-4" {
					dst += "/32"
				} else {
					dst += "/128"
				}
			}
			route := RuntimeRoute{Route: Route{dst, r.Gateway, r.Dev, r.Metric}, Protocol: textValue(r.Protocol), Source: r.Source, Scope: r.Scope}
			for _, f := range r.Flags {
				if f == "onlink" {
					route.Onlink = true
				}
			}
			if r.Dev == "" || len(r.Multipath) > 0 || (r.Type != "" && r.Type != "unicast") {
				route.Protocol = "unsupported"
			}
			routes = append(routes, route)
		}
	}
	return out, routes, nil
}
