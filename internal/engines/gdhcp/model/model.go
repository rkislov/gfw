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

package model

import "time"

const (
	StateOffered  = "offered"
	StateBound    = "bound"
	StateReleased = "released"
	StateExpired  = "expired"
	StateDeclined = "declined"
)

// Lease is one DHCP binding.
type Lease struct {
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	ClientID   string    `json:"client_id,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	SubnetID   string    `json:"subnet_id"`
	VLANID     *int      `json:"vlan_id,omitempty"`
	GIAddr     string    `json:"giaddr,omitempty"`
	CircuitID  string    `json:"circuit_id,omitempty"`
	RemoteID   string    `json:"remote_id,omitempty"`
	LinkSelect string    `json:"link_select,omitempty"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

func (l Lease) ActiveAt(now time.Time) bool {
	switch l.State {
	case StateOffered, StateBound, StateDeclined:
		return l.ExpiresAt.After(now)
	default:
		return false
	}
}

// VLAN is a configured or persisted VLAN.
type VLAN struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"`
	Priority  int    `json:"priority"`
	Source    string `json:"source,omitempty"`
	SubnetID  string `json:"subnet_id,omitempty"`
}

// Subnet is a persisted subnet row. Options is a JSON object.
type Subnet struct {
	ID         string            `json:"id"`
	Network    string            `json:"network"`
	RangeStart string            `json:"range_start,omitempty"`
	RangeEnd   string            `json:"range_end,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	VLANID     *int              `json:"vlan_id,omitempty"`
	Domain     string            `json:"domain,omitempty"`
	DNS        []string          `json:"dns,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	LeaseSec   int               `json:"lease_seconds,omitempty"`
}

// Relay is a known or trusted relay agent.
type Relay struct {
	GIAddr     string    `json:"giaddr"`
	RemoteID   string    `json:"remote_id,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Trusted    bool      `json:"trusted"`
	ParserName string    `json:"parser_name,omitempty"`
	VLANID     *int      `json:"vlan_id,omitempty"`
	SubnetID   string    `json:"subnet_id,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

// Reservation is a static binding.
type Reservation struct {
	ID       int64  `json:"id"`
	MAC      string `json:"mac,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	SubnetID string `json:"subnet_id"`
}

// LeaseFilter selects leases for list queries.
type LeaseFilter struct {
	AllowedSubnets []string // nil is unrestricted; empty denies all.
	AllowedVLANs   []int    // nil is unrestricted; empty permits only untagged leases.
	VLAN           *int
	SubnetID       string
	GIAddr         string
	Query          string
	State          string
	Limit          int
	Offset         int
}

// RelayStats is the in-memory counter snapshot exposed by the API.
type RelayStats struct {
	GIAddr       string    `json:"giaddr"`
	Requests     uint64    `json:"requests"`
	UnknownVLAN  uint64    `json:"unknown_vlan"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	LastCircuit  string    `json:"last_circuit_id,omitempty"`
	LastRemoteID string    `json:"last_remote_id,omitempty"`
	LastVLAN     *int      `json:"last_vlan,omitempty"`
}
