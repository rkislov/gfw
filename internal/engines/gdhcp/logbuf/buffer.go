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

package logbuf

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Buffer keeps a ring of formatted log lines and fans them out to subscribers.
type Buffer struct {
	mu    sync.Mutex
	lines []string
	cap   int
	subs  map[int]chan string
	next  int
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 500
	}
	return &Buffer{cap: capacity, subs: map[int]chan string{}}
}

func (b *Buffer) Append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.lines) < b.cap {
		b.lines = append(b.lines, line)
	} else {
		off := len(b.lines) - b.cap + 1
		if off < 1 {
			off = 1
		}
		b.lines = append(b.lines[off:], line)
	}
	for _, ch := range b.subs {
		select {
		case ch <- line:
		default:
		}
	}
}

// Recent returns a copy of the buffered lines.
func (b *Buffer) Recent() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

// Subscribe returns a channel of new lines and an unsubscribe function.
func (b *Buffer) Subscribe() (<-chan string, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	id := b.next
	ch := make(chan string, 32)
	b.subs[id] = ch
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subs, id)
	}
}

// Handler is a slog handler that records the formatted record and forwards it.
type Handler struct {
	next slog.Handler
	buf  *Buffer
}

func NewHandler(next slog.Handler, buf *Buffer) *Handler {
	return &Handler{next: next, buf: buf}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.buf != nil {
		var b strings.Builder
		b.WriteString(r.Time.Format("2006-01-02T15:04:05.000Z07:00"))
		b.WriteByte(' ')
		b.WriteString(r.Level.String())
		b.WriteByte(' ')
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteByte(' ')
			b.WriteString(a.Key)
			b.WriteByte('=')
			b.WriteString(a.Value.String())
			return true
		})
		h.buf.Append(b.String())
	}
	if h.next == nil {
		return nil
	}
	return h.next.Handle(ctx, r)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := slog.Handler(nil)
	if h.next != nil {
		next = h.next.WithAttrs(attrs)
	}
	return &Handler{next: next, buf: h.buf}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	next := slog.Handler(nil)
	if h.next != nil {
		next = h.next.WithGroup(name)
	}
	return &Handler{next: next, buf: h.buf}
}
