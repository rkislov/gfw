// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package ddns

import (
	"context"
	"fmt"
	"github.com/rkislov/gfw/internal/engines/gdhcp/config"
	"github.com/rkislov/gfw/internal/engines/gdhcp/storage"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
)

func record() storage.DNSRecord {
	return storage.DNSRecord{Server: "dc.example.org:53", Zone: "hosts.example.org.", Name: "client.hosts.example.org.", Type: "A", Value: "192.0.2.1", Token: strings.Repeat("a", 64), TTL: 300}
}
func TestSignedUpdatesUseAtomicOwnershipGuards(t *testing.T) {
	ctx := context.Background()
	calls := []string{}
	c := &nsClient{cfg: config.DDNS{Auth: "gss-tsig", TimeoutSeconds: 2}, exec: func(ctx context.Context, name string, args, env []string, in string) (string, error) {
		require.Equal(t, "nsupdate", name)
		require.Contains(t, args, "-g")
		calls = append(calls, in)
		if len(calls) == 1 {
			return "update failed: NXRRSET", fmt.Errorf("exit 2")
		}
		return "", nil
	}}
	require.NoError(t, c.Set(ctx, record()))
	require.Len(t, calls, 2)
	require.Contains(t, calls[0], `prereq yxrrset _godhcp-owner.client.hosts.example.org. TXT "`+record().Token+`"`)
	require.Contains(t, calls[1], "prereq nxrrset client.hosts.example.org. A\n")
	require.Contains(t, calls[1], "prereq nxrrset client.hosts.example.org. CNAME\n")
	require.Contains(t, calls[1], "update add _godhcp-owner.client.hosts.example.org. 300 TXT")
	calls = nil
	c.exec = func(context.Context, string, []string, []string, string) (string, error) {
		return "update failed: REFUSED", fmt.Errorf("exit 2")
	}
	require.Error(t, c.Set(ctx, record()))
	bad := record()
	bad.Name = "victim.example.org.\nupdate delete example.org ANY"
	require.Error(t, c.Set(ctx, bad))
}
func TestDeleteDoesNotTouchUnmanagedRecord(t *testing.T) {
	calls := []string{}
	c := &nsClient{cfg: config.DDNS{Auth: "gss-tsig", TimeoutSeconds: 2}, exec: func(ctx context.Context, name string, args, env []string, in string) (string, error) {
		calls = append(calls, in)
		if len(calls) == 1 {
			return "NXRRSET", fmt.Errorf("not owned")
		}
		return "", nil
	}}
	require.NoError(t, c.Remove(context.Background(), record()))
	require.Len(t, calls, 2)
	require.NotContains(t, calls[1], "update delete")
	require.Contains(t, calls[1], "prereq nxrrset _godhcp-owner.")
}
func TestKeytabLoginUsesPrivateDisposableCache(t *testing.T) {
	t.Setenv("KRB5CCNAME", "FILE:/do-not-use-user-cache")
	var cache string
	w, _, _, _ := fixture(t)
	run := func(ctx context.Context, name string, args, env []string, in string) (string, error) {
		require.Equal(t, "kinit", name)
		require.Equal(t, []string{"-k", "-t", "/tmp/keytab", "dhcp-dns@EXAMPLE.ORG"}, args)
		for _, v := range env {
			if strings.HasPrefix(v, "KRB5CCNAME=") {
				require.NotContains(t, v, "do-not-use")
				cache = strings.TrimPrefix(v, "KRB5CCNAME=FILE:")
			}
		}
		info, e := os.Stat(strings.TrimSuffix(cache, "/ticket"))
		require.NoError(t, e)
		require.EqualValues(t, 0700, info.Mode().Perm())
		return "", nil
	}
	c, closeSession, e := session(context.Background(), w.config().DDNS, run)
	require.NoError(t, e)
	require.NotNil(t, c)
	closeSession()
	_, e = os.Stat(strings.TrimSuffix(cache, "/ticket"))
	require.True(t, os.IsNotExist(e))
}

func TestSambaReadbackRequiresExactAuthenticatedState(t *testing.T) {
	for _, scenario := range []string{"confirmed", "foreign", "wrong-value", "wrong-ttl", "truncated", "rpc-failure", "refused", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			c := &nsClient{cfg: config.DDNS{Auth: "gss-tsig", TimeoutSeconds: 2}, env: []string{"KRB5CCNAME=FILE:/private/ticket"}}
			if scenario == "disabled" {
				no := false
				c.cfg.SambaVerify = &no
			}
			c.exec = func(ctx context.Context, name string, args, env []string, in string) (string, error) {
				if name == "nsupdate" {
					if scenario == "refused" {
						return "REFUSED", fmt.Errorf("exit 2")
					}
					return "tsig verify failure", fmt.Errorf("exit 2")
				}
				calls++
				require.Equal(t, "samba-tool", name)
				require.Contains(t, args, "--use-kerberos=required")
				require.Contains(t, args, "--use-krb5-ccache=FILE:/private/ticket")
				require.Contains(t, args, "--no-pass")
				if scenario == "rpc-failure" {
					return "access denied", fmt.Errorf("exit 1")
				}
				if args[5] == "TXT" {
					token := record().Token
					if scenario == "foreign" {
						token = strings.Repeat("b", 64)
					}
					return fmt.Sprintf("  Name=, Records=1, Children=0\n    TXT: %q (flags=f0, serial=1, ttl=300)\n", token), nil
				}
				value, ttl, count := "192.0.2.1", 300, 1
				if scenario == "wrong-value" {
					value = "192.0.2.2"
				}
				if scenario == "wrong-ttl" {
					ttl = 60
				}
				if scenario == "truncated" {
					count = 2
				}
				return fmt.Sprintf("  Name=, Records=%d, Children=0\n    A: %s (flags=f0, serial=1, ttl=%d)\n", count, value, ttl), nil
			}
			err := c.Set(context.Background(), record())
			if scenario == "confirmed" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if scenario == "disabled" || scenario == "refused" {
				require.Zero(t, calls)
			}
		})
	}
}
