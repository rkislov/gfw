// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package ddns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
)

type executor func(context.Context, string, []string, []string, string) (string, error)
type nsClient struct {
	cfg  config.DDNS
	env  []string
	exec executor
}

func CheckTools(c config.DDNS) error {
	tools := []string{"nsupdate"}
	if c.Auth == "gss-tsig" {
		tools = append(tools, "kinit")
		if enabled(c.SambaVerify) {
			tools = append(tools, "samba-tool")
		}
	}
	for _, name := range tools {
		if _, e := exec.LookPath(name); e != nil {
			return fmt.Errorf("DDNS requires %s in service PATH", name)
		}
	}
	return nil
}

type cappedOutput struct{ b strings.Builder }

func (w *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - w.b.Len(); remaining > 0 {
		if remaining < len(p) {
			p = p[:remaining]
		}
		w.b.Write(p)
	}
	return n, nil
}
func execute(ctx context.Context, name string, args, env []string, input string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(input)
	out := &cappedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return out.b.String(), err
}
func newSession(ctx context.Context, c config.DDNS) (Updater, func(), error) {
	return session(ctx, c, execute)
}
func session(ctx context.Context, c config.DDNS, run executor) (Updater, func(), error) {
	dir, e := os.MkdirTemp("", "godhcp-ddns-")
	if e != nil {
		return nil, nil, e
	}
	closeSession := func() { os.RemoveAll(dir) }
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "KRB5CCNAME=") && !strings.HasPrefix(v, "LC_ALL=") {
			env = append(env, v)
		}
	}
	env = append(env, "KRB5CCNAME=FILE:"+dir+"/ticket", "LC_ALL=C")
	if c.Auth == "gss-tsig" {
		init, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
		defer cancel()
		if _, e := run(init, "kinit", []string{"-k", "-t", c.Keytab, c.Principal}, env, ""); e != nil {
			closeSession()
			return nil, nil, fmt.Errorf("DDNS Kerberos login failed: check keytab, principal, KDC, DNS and time synchronization")
		}
	}
	return &nsClient{cfg: c, env: env, exec: run}, closeSession, nil
}
func validRecord(r storage.DNSRecord) bool {
	host, port, e := net.SplitHostPort(r.Server)
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || n < 1 || n > 65535 {
		return false
	}
	if !config.DNSName(host) {
		if _, e := netip.ParseAddr(host); e != nil {
			return false
		}
	}
	if !config.DNSName(r.Name) || !config.DNSName(r.Zone) || !strings.HasSuffix(r.Name, "."+r.Zone) || len(r.Token) != 64 || r.TTL < 1 {
		return false
	}
	for _, ch := range r.Token {
		if !(ch >= 'a' && ch <= 'f') && !(ch >= '0' && ch <= '9') {
			return false
		}
	}
	if r.Type == "A" {
		ip, e := netip.ParseAddr(r.Value)
		return e == nil && ip.Is4()
	}
	return r.Type == "PTR" && config.DNSName(r.Value)
}
func (c *nsClient) send(ctx context.Context, r storage.DNSRecord, body string) error {
	if !validRecord(r) {
		return fmt.Errorf("invalid DDNS record")
	}
	host, port, _ := net.SplitHostPort(r.Server)
	input := "server " + host + " " + port + "\nzone " + r.Zone + "\n" + body + "send\n"
	args := []string{"-v", "-t", strconv.Itoa(c.cfg.TimeoutSeconds)}
	if c.cfg.Auth == "gss-tsig" {
		args = append(args, "-g")
	} else {
		args = append(args, "-k", c.cfg.KeyFile)
	}
	timeout, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	out, e := c.exec(timeout, "nsupdate", args, c.env, input)
	if e != nil {
		return fmt.Errorf("nsupdate: %w: %s", e, strings.TrimSpace(out))
	}
	return nil
}
func (c *nsClient) Set(ctx context.Context, r storage.DNSRecord) error {
	marker := "_godhcp-owner." + r.Name
	update := fmt.Sprintf("update delete %s %s\nupdate add %s %d %s %s\n", r.Name, r.Type, r.Name, r.TTL, r.Type, r.Value)
	owned := fmt.Sprintf("prereq yxrrset %s TXT \"%s\"\n", marker, r.Token) + update
	err := c.confirm(ctx, r, c.send(ctx, r, owned), false)
	if err == nil {
		return nil
	}
	// Only a missing ownership marker permits a claim attempt. Network/auth
	// failures and foreign ownership are never converted to an insecure update.
	if !strings.Contains(err.Error(), "NXRRSET") {
		return err
	}
	claim := fmt.Sprintf("prereq nxrrset %s TXT\nprereq nxrrset %s %s\nprereq nxrrset %s CNAME\nupdate add %s %d TXT \"%s\"\nupdate add %s %d %s %s\n", marker, r.Name, r.Type, r.Name, marker, r.TTL, r.Token, r.Name, r.TTL, r.Type, r.Value)
	return c.confirm(ctx, r, c.send(ctx, r, claim), false)
}
func (c *nsClient) Remove(ctx context.Context, r storage.DNSRecord) error {
	marker := "_godhcp-owner." + r.Name
	body := fmt.Sprintf("prereq yxrrset %s TXT \"%s\"\nupdate delete %s %s\nupdate delete %s TXT \"%s\"\n", marker, r.Token, r.Name, r.Type, marker, r.Token)
	err := c.confirm(ctx, r, c.send(ctx, r, body), true)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "NXRRSET") {
		return err
	}
	// Marker absent => the record is already gone or has become unmanaged.
	// A prerequisite-only request verifies this without touching the data.
	return c.confirm(ctx, r, c.send(ctx, r, "prereq nxrrset "+marker+" TXT\n"), true)
}

var _ io.Writer = (*cappedOutput)(nil)

// Some Samba Internal DNS versions apply an update but return a response that
// nsupdate cannot authenticate. Never ignore that failure: independently read
// the result using DNS RPC with mandatory Kerberos and signed transport.
func (c *nsClient) confirm(ctx context.Context, r storage.DNSRecord, updateErr error, removing bool) error {
	if updateErr == nil {
		return nil
	}
	if c.cfg.Auth != "gss-tsig" || !enabled(c.cfg.SambaVerify) || !strings.Contains(strings.ToLower(updateErr.Error()), "tsig verify failure") {
		return updateErr
	}
	marker, err := c.queryRPC(ctx, r, "_godhcp-owner."+r.Name, "TXT")
	if err == nil {
		if removing && len(marker) == 0 {
			return nil
		}
		if !removing && len(marker) == 1 && marker[0].value == "\""+r.Token+"\"" {
			var data []rpcRecord
			data, err = c.queryRPC(ctx, r, r.Name, r.Type)
			if err == nil && len(data) == 1 {
				value := data[0].value
				if r.Type == "PTR" {
					value = canonical(value)
				}
				if value == r.Value && data[0].ttl == r.TTL {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w; authenticated Samba RPC did not confirm the desired state", updateErr)
}

type rpcRecord struct {
	value string
	ttl   uint32
}

var rpcCount = regexp.MustCompile(`(?m)^\s*Name=[^\n]*, Records=([0-9]+), Children=[0-9]+\s*$`)

var rpcLine = regexp.MustCompile(`^\s*(A|PTR|TXT): (.+) \(flags=[^,]+, serial=[0-9]+, ttl=([0-9]+)\)\s*$`)

func (c *nsClient) queryRPC(ctx context.Context, r storage.DNSRecord, name, typ string) ([]rpcRecord, error) {
	host, _, _ := net.SplitHostPort(r.Server)
	relative := strings.TrimSuffix(name, "."+r.Zone)
	args := []string{"dns", "query", host, strings.TrimSuffix(r.Zone, "."), relative, typ, "--use-kerberos=required", "--no-pass", "--authority", "--no-children"}
	for _, v := range c.env {
		if strings.HasPrefix(v, "KRB5CCNAME=") {
			args = append(args, "--use-krb5-ccache="+strings.TrimPrefix(v, "KRB5CCNAME="))
			break
		}
	}
	timeout, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	out, err := c.exec(timeout, "samba-tool", args, c.env, "")
	if err != nil {
		if strings.Contains(out, "ERROR: Record or zone does not exist.") {
			return []rpcRecord{}, nil
		}
		return nil, fmt.Errorf("authenticated Samba DNS query failed")
	}
	records := []rpcRecord{}
	for _, line := range strings.Split(out, "\n") {
		match := rpcLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if match[1] != typ {
			return nil, fmt.Errorf("unexpected Samba DNS record type")
		}
		ttl, e := strconv.ParseUint(match[3], 10, 32)
		if e != nil {
			return nil, e
		}
		records = append(records, rpcRecord{value: match[2], ttl: uint32(ttl)})
	}
	// Unrecognized/truncated output must not be mistaken for authoritative absence.
	counts := rpcCount.FindAllStringSubmatch(out, -1)
	if len(counts) != 1 {
		return nil, fmt.Errorf("unrecognized Samba DNS query header")
	}
	count, countErr := strconv.Atoi(counts[0][1])
	if countErr != nil || count != len(records) {
		return nil, fmt.Errorf("unrecognized Samba DNS query output")
	}
	return records, nil
}
