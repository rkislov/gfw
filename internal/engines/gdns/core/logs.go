// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"github.com/miekg/dns"
	"net/netip"
	"sync"
	"time"
)

type LogPage struct {
	Items    []QueryLog `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int        `json:"total"`
	Pages    int        `json:"pages"`
	Anchor   uint64     `json:"anchor"`
	Capacity int        `json:"capacity"`
}

// Strings needed by the API are formatted only for the requested page, outside
// the journal lock. DNS workers retain numeric timestamps, IPs and RR types.
type logEntry struct {
	id       uint64
	at       int64
	client   netip.Addr
	name     string
	qtype    uint16
	result   string
	duration float64
}

func renderLogs(entries []logEntry) []QueryLog {
	out := make([]QueryLog, len(entries))
	for i, q := range entries {
		out[i] = QueryLog{ID: q.id, Time: time.Unix(0, q.at).UTC().Format(time.RFC3339), Client: q.client.String(), Name: q.name, Type: dns.TypeToString[q.qtype], Result: q.result, Duration: q.duration}
	}
	return out
}

// Each writer holds a shared resize lock and owns only its destination slot.
// Snapshots take the exclusive lock, waiting for all reserved IDs to publish.
// This preserves contiguous anchors without dropping queued events.
type logSlot struct {
	mu    sync.Mutex
	entry logEntry
	_     [32]byte // Separate neighboring writers on common cache-line sizes.
}

// Caller must hold logMu exclusively.
func (e *Engine) logRange() (newest uint64, count int) {
	newest = e.logSequence.Load()
	if e.logFloor > newest {
		return newest, 0
	}
	return newest, min(e.logLimit, int(newest-e.logFloor+1))
}
func (e *Engine) resizeLogs(capacity int) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	if capacity == e.logLimit {
		return
	}
	newest, count := e.logRange()
	count = min(capacity, count)
	slots := make([]logSlot, capacity)
	for i := 0; i < count; i++ {
		id := newest - uint64(i)
		slots[(id-1)%uint64(capacity)].entry = e.logs[(id-1)%uint64(e.logLimit)].entry
	}
	e.logs = slots
	e.logLimit = capacity
	e.logFloor = newest - uint64(count) + 1
}
func (e *Engine) appendLog(q logEntry) {
	e.logMu.RLock()
	defer e.logMu.RUnlock()
	q.id = e.logSequence.Add(1)
	slot := &e.logs[(q.id-1)%uint64(e.logLimit)]
	slot.mu.Lock()
	// A descheduled writer can resume after its slot has already wrapped.
	// Never overwrite a newer retained event with that older event.
	if slot.entry.id < q.id {
		slot.entry = q
	}
	slot.mu.Unlock()
}

// log is retained for internal callers supplying already formatted events.
func (e *Engine) log(q QueryLog) {
	at, _ := time.Parse(time.RFC3339, q.Time)
	ip, _ := netip.ParseAddr(q.Client)
	e.appendLog(logEntry{at: at.UnixNano(), client: ip, name: q.Name, qtype: dns.StringToType[q.Type], result: q.Result, duration: q.Duration})
}
func (e *Engine) RecentLogs(limit int) []QueryLog {
	e.logMu.Lock()
	newest, count := e.logRange()
	n := max(0, min(limit, count))
	entries := make([]logEntry, n)
	for i := range entries {
		id := newest - uint64(i)
		entries[i] = e.logs[(id-1)%uint64(e.logLimit)].entry
	}
	e.logMu.Unlock()
	return renderLogs(entries)
}
func (e *Engine) Logs() []QueryLog { return e.RecentLogs(100000) }

// IDs in the bounded ring are contiguous, even after a resize. Compute eligible
// rows and offsets from IDs instead of scanning up to 100,000 entries under lock.
func (e *Engine) QueryLogs(page, size int, anchor uint64) LogPage {
	page = max(1, page)
	size = max(1, min(100, size))
	entries := make([]logEntry, size)
	e.logMu.Lock()
	newest, n := e.logRange()
	if anchor == 0 && n > 0 {
		anchor = newest
	}
	total := 0
	eligibleNewest := min(anchor, newest)
	if n > 0 {
		oldest := newest - uint64(n) + 1
		if eligibleNewest >= oldest {
			total = int(eligibleNewest - oldest + 1)
		}
	}
	pages := max(1, (total+size-1)/size)
	page = min(page, pages)
	skip := (page - 1) * size
	count := min(size, total-skip)
	entries = entries[:count]
	for i := 0; i < count; i++ {
		id := eligibleNewest - uint64(skip+i)
		entries[i] = e.logs[(id-1)%uint64(e.logLimit)].entry
	}
	capacity := e.logLimit
	e.logMu.Unlock()
	return LogPage{Items: renderLogs(entries), Page: page, PageSize: size, Total: total, Pages: pages, Anchor: anchor, Capacity: capacity}
}
