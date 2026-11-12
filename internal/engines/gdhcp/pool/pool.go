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

package pool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var (
	ErrUnknownSubnet = errors.New("unknown subnet")
	ErrExhausted     = errors.New("pool exhausted")
	ErrConflict      = errors.New("address in use")
	ErrNotInPool     = errors.New("address is outside the pool")
)

// Reservation is a static binding inside one subnet.
type Reservation struct {
	IP       netip.Addr
	MAC      string
	ClientID string
	Hostname string
}

// Spec describes one dynamic pool.
type Spec struct {
	ID           string
	Prefix       netip.Prefix
	Start        netip.Addr
	End          netip.Addr
	Gateway      netip.Addr
	VLAN         int
	Reservations []Reservation
}

// Binding is an in-memory occupancy record.
type Binding struct {
	IP       string
	MAC      string
	ClientID string
}

// Stat is pool occupancy for metrics and the UI.
type Stat struct {
	ID   string
	VLAN int
	Size int
	Used int
	Free int
}

// Manager is the in-memory address index. The database remains the source of
// truth across restarts; this index makes allocation a memory operation.
type Manager struct {
	mu    sync.Mutex
	pools map[string]*state
}

type state struct {
	spec     Spec
	used     map[string]string // ip -> mac (empty mac means declined/held)
	byMAC    map[string]string // mac -> ip
	byClient map[string]string // client-id -> ip
	reserved map[string]Reservation
	byResMAC map[string]string
	byResCID map[string]string
}

func New() *Manager {
	return &Manager{pools: map[string]*state{}}
}

// Reconcile replaces pool definitions and reloads active bindings.
func (m *Manager) Reconcile(specs []Spec, active []Binding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := make(map[string]*state, len(specs))
	for _, spec := range specs {
		st := &state{
			spec:     spec,
			used:     map[string]string{},
			byMAC:    map[string]string{},
			byClient: map[string]string{},
			reserved: map[string]Reservation{},
			byResMAC: map[string]string{},
			byResCID: map[string]string{},
		}
		for _, r := range spec.Reservations {
			ip := r.IP.String()
			st.reserved[ip] = r
			if r.MAC != "" {
				st.byResMAC[r.MAC] = ip
			}
			if r.ClientID != "" {
				st.byResCID[r.ClientID] = ip
			}
			st.used[ip] = r.MAC
			if r.MAC != "" {
				st.byMAC[r.MAC] = ip
			}
		}
		next[spec.ID] = st
	}
	m.pools = next
	for _, b := range active {
		st := m.poolForIPLocked(b.IP)
		if st == nil {
			continue
		}
		st.rebind(b.IP, b.MAC)
		st.used[b.IP] = b.MAC
		if b.ClientID != "" {
			st.byClient[b.ClientID] = b.IP
		}
	}
}

func (m *Manager) poolForIPLocked(ip string) *state {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	for _, st := range m.pools {
		if st.spec.Prefix.IsValid() && st.spec.Prefix.Contains(addr) {
			return st
		}
	}
	return nil
}

// Allocate picks an address for mac inside the subnet. The address is marked
// used before the function returns. When strict is set, requested must be
// usable for this client; another free address is not substituted.
func (m *Manager) Allocate(subnetID, mac, clientID string, requested netip.Addr, strict bool) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.pools[subnetID]
	if !ok {
		return netip.Addr{}, ErrUnknownSubnet
	}
	if ip, ok := st.byResMAC[mac]; ok {
		if strict && requested.IsValid() && !requested.IsUnspecified() && ip != requested.String() {
			return netip.Addr{}, ErrConflict
		}
		return netip.MustParseAddr(ip), nil
	}
	if clientID != "" {
		if ip, ok := st.byResCID[clientID]; ok {
			if strict && requested.IsValid() && !requested.IsUnspecified() && ip != requested.String() {
				return netip.Addr{}, ErrConflict
			}
			return netip.MustParseAddr(ip), nil
		}
	}
	if requested.IsValid() && !requested.IsUnspecified() && strict {
		if err := st.claim(requested, mac, clientID); err != nil {
			return netip.Addr{}, err
		}
		return requested, nil
	}
	if ip, ok := st.byMAC[mac]; ok {
		if _, held := st.reserved[ip]; !held || st.reserved[ip].MAC == mac {
			return netip.MustParseAddr(ip), nil
		}
	}
	if requested.IsValid() && !requested.IsUnspecified() {
		if err := st.claim(requested, mac, clientID); err == nil {
			return requested, nil
		}
	}
	var found netip.Addr
	foundOK := false
	eachAddr(st.spec.Start, st.spec.End, func(ip netip.Addr) bool {
		if st.excluded(ip) {
			return true
		}
		if owner, used := st.used[ip.String()]; used && owner != mac {
			return true
		}
		if err := st.claim(ip, mac, clientID); err == nil {
			found = ip
			foundOK = true
			return false
		}
		return true
	})
	if !foundOK {
		return netip.Addr{}, ErrExhausted
	}
	return found, nil
}

// Holds reports whether ip is currently occupied by someone other than mac.
func (m *Manager) Holds(subnetID, mac string, ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.pools[subnetID]
	if !ok {
		return false
	}
	owner, used := st.used[ip.String()]
	return used && owner != "" && owner != mac
}

// Contains reports whether ip belongs to the dynamic range or a reservation.
func (m *Manager) Contains(subnetID string, ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.pools[subnetID]
	if !ok {
		return false
	}
	if _, ok := st.reserved[ip.String()]; ok {
		return true
	}
	if !st.spec.Start.IsValid() || !st.spec.End.IsValid() {
		return st.spec.Prefix.Contains(ip)
	}
	return ip.Compare(st.spec.Start) >= 0 && ip.Compare(st.spec.End) <= 0 && st.spec.Prefix.Contains(ip)
}

// Release frees a dynamic address. Reservations stay occupied.
func (m *Manager) Release(ip, mac string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.poolForIPLocked(ip)
	if st == nil {
		return
	}
	if r, ok := st.reserved[ip]; ok {
		st.rebind(ip, r.MAC)
		st.used[ip] = r.MAC
		return
	}
	if owner, ok := st.used[ip]; ok && (mac == "" || owner == mac) {
		delete(st.used, ip)
		if owner != "" && st.byMAC[owner] == ip {
			delete(st.byMAC, owner)
		}
	}
}

// Hold keeps ip out of the pool until the caller releases it. Reservations are left alone.
func (m *Manager) Hold(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.poolForIPLocked(ip)
	if st == nil {
		return
	}
	if _, reserved := st.reserved[ip]; reserved {
		return
	}
	st.rebind(ip, "")
	st.used[ip] = "*held*"
}

// Bind forces occupancy, used when restoring a lease.
func (m *Manager) Bind(subnetID, ip, mac, clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.pools[subnetID]
	if !ok {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	_ = st.claim(addr, mac, clientID)
}

func (st *state) claim(ip netip.Addr, mac, clientID string) error {
	key := ip.String()
	if r, ok := st.reserved[key]; ok {
		macOK := r.MAC != "" && r.MAC == mac
		cidOK := r.ClientID != "" && r.ClientID == clientID
		if !macOK && !cidOK {
			return ErrConflict
		}
		st.rebind(key, mac)
		st.used[key] = mac
		return nil
	}
	if !st.inRange(ip) || st.excluded(ip) {
		return ErrNotInPool
	}
	if owner, used := st.used[key]; used && owner != "" && owner != mac {
		return ErrConflict
	}
	// A previous address may still have a valid persisted lease. Only an
	// explicit release or reconciliation with storage may free that address.
	st.rebind(key, mac)
	st.used[key] = mac
	if clientID != "" {
		st.byClient[clientID] = key
	}
	return nil
}

func (st *state) rebind(ip, mac string) {
	// used is the reverse index. A MAC may retain several committed leases;
	// only remove its preferred-address entry if that entry names this IP.
	if previous := st.used[ip]; previous != "" && previous != mac && st.byMAC[previous] == ip {
		delete(st.byMAC, previous)
	}
	if mac != "" {
		st.byMAC[mac] = ip
	}
}

func (st *state) inRange(ip netip.Addr) bool {
	if !st.spec.Start.IsValid() || !st.spec.End.IsValid() {
		return false
	}
	return ip.Compare(st.spec.Start) >= 0 && ip.Compare(st.spec.End) <= 0
}

func (st *state) excluded(ip netip.Addr) bool {
	if st.spec.Gateway.IsValid() && ip == st.spec.Gateway {
		return true
	}
	if !st.spec.Prefix.IsValid() {
		return false
	}
	if ip == st.spec.Prefix.Masked().Addr() {
		return true
	}
	if ip == broadcast(st.spec.Prefix) {
		return true
	}
	return false
}

// Stats returns occupancy. Reserved addresses count as used.
func (m *Manager) Stats() []Stat {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Stat, 0, len(m.pools))
	for id, st := range m.pools {
		size := 0
		eachAddr(st.spec.Start, st.spec.End, func(ip netip.Addr) bool {
			if !st.excluded(ip) {
				size++
			}
			return true
		})
		used := len(st.used)
		free := size - used
		if free < 0 {
			free = 0
		}
		out = append(out, Stat{ID: id, VLAN: st.spec.VLAN, Size: size, Used: used, Free: free})
	}
	return out
}

func broadcast(p netip.Prefix) netip.Addr {
	base := p.Masked().Addr().As4()
	hostBits := 32 - p.Bits()
	var hostMask uint32
	if hostBits >= 32 {
		hostMask = ^uint32(0)
	} else if hostBits > 0 {
		hostMask = uint32(1<<uint(hostBits)) - 1
	}
	ip := binary.BigEndian.Uint32(base[:]) | hostMask
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return netip.AddrFrom4(b)
}

func eachAddr(start, end netip.Addr, fn func(netip.Addr) bool) {
	if !start.IsValid() || !end.IsValid() || start.Compare(end) > 0 {
		return
	}
	ip := start
	for {
		if !fn(ip) {
			return
		}
		if ip == end {
			return
		}
		next := ip.Next()
		if !next.IsValid() || next.Compare(end) > 0 {
			return
		}
		ip = next
	}
}

// SubnetOf returns the pool id that contains ip.
func (m *Manager) SubnetOf(ip netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, st := range m.pools {
		if st.spec.Prefix.IsValid() && st.spec.Prefix.Contains(ip) {
			return id, true
		}
	}
	return "", false
}

func (m *Manager) String() string {
	stats := m.Stats()
	return fmt.Sprintf("pools=%d", len(stats))
}
