// Copyright 2026 Кислов Роман Сергеевич
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpandEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "s3cret")
	got := ExpandEnv("token=${JWT_SECRET} fallback=${MISSING:-dev} lit=$${JWT_SECRET}")
	require.Equal(t, "token=s3cret fallback=dev lit=${JWT_SECRET}", got)
}

func TestParseExampleShape(t *testing.T) {
	raw := []byte(`
server:
  interfaces:
    - name: eth0
      mode: trunk
      vlans: [10, 20]
  authoritative: true
  ping_check: false
  lease_default: 24h
  lease_max: 72h
  server_id: 192.168.10.1
database:
  driver: sqlite
  dsn: /tmp/godhcp.db
api:
  listen: ":8080"
  auth:
    jwt_secret: "dev-secret-dev-secret-dev-secret"
    token_ttl: 1h
vlans:
  - id: 10
    name: office
    interface: eth0.10
    priority: 5
    subnet_ref: office-lan
subnets:
  - id: office-lan
    network: 192.168.10.0/24
    range: [192.168.10.100, 192.168.10.200]
    gateway: 192.168.10.1
    dns: [1.1.1.1, 8.8.8.8]
    domain: lan.local
relay:
  enabled: true
  max_relay_hops: 4
  circuit_id_parsers:
    - name: cisco
      regex: '^(?P<port>[^:]+):vlan(?P<vlan>\d+)$'
      vlan_group: vlan
logging:
  level: info
  format: json
`)
	cfg, err := Parse(raw, "memory")
	require.NoError(t, err)
	require.Equal(t, 24*time.Hour, cfg.Server.LeaseDefault)
	require.Equal(t, 4, cfg.Relay.MaxRelayHops)
	require.True(t, cfg.EchoOption82())
	require.NotNil(t, cfg.Subnets[0].VLAN)
	require.Equal(t, 10, *cfg.Subnets[0].VLAN)
	require.Equal(t, "/ui", cfg.Web.Path)
}

func TestRejectsOverlapAndBadRegex(t *testing.T) {
	raw := []byte(`
server:
  lease_default: 48h
  lease_max: 1h
database:
  driver: sqlite
  dsn: /tmp/x.db
subnets:
  - id: a
    network: 10.0.0.0/24
    range: [10.0.0.10, 10.0.0.50]
  - id: b
    network: 10.0.0.0/24
    range: [10.0.0.40, 10.0.0.80]
relay:
  circuit_id_parsers:
    - name: bad
      regex: '('
`)
	_, err := Parse(raw, "memory")
	require.Error(t, err)
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	cfg := &Config{}
	cfg.Database.DSN = filepath.Join(dir, "leases.db")
	cfg.Server.ServerID = "192.168.1.1"
	cfg.Subnets = []Subnet{{
		ID:      "lan",
		Network: "192.168.1.0/24",
		Range:   []string{"192.168.1.10", "192.168.1.20"},
		Gateway: "192.168.1.1",
	}}
	cfg.ApplyDefaults()
	require.NoError(t, cfg.Validate())
	require.NoError(t, Save(path, cfg))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "lan", loaded.Subnets[0].ID)
	_, err = os.Stat(path)
	require.NoError(t, err)
}
