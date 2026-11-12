package capture

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	_ "modernc.org/sqlite"
)

const DefaultQuotaMiB = 512
const maxSessions = 32

var (
	ErrBusy    = errors.New("уже выполняется захват пакетов")
	ErrMissing = errors.New("сессия захвата не найдена")
	ErrActive  = errors.New("сначала остановите захват")
	ErrQuota   = errors.New("исчерпана квота захвата или каталог заполнен")
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Session struct {
	ID       string     `json:"id"`
	Config   Config     `json:"config"`
	Filter   string     `json:"filter"`
	Backend  string     `json:"backend"`
	Fallback string     `json:"fallback,omitempty"`
	State    string     `json:"state"`
	Reason   string     `json:"reason,omitempty"`
	Error    string     `json:"error,omitempty"`
	Start    time.Time  `json:"start"`
	End      *time.Time `json:"end,omitempty"`
	Expires  time.Time  `json:"expires"`
	captureStats
	Dropped    *uint64   `json:"dropped,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	Segments   []Segment `json:"segments,omitempty"`
	RotatedOut int       `json:"rotated_out,omitempty"`
}

type captureStats struct {
	Packets       uint64 `json:"packets"`
	OriginalBytes uint64 `json:"original_bytes"`
	CapturedBytes uint64 `json:"captured_bytes"`
	Truncated     uint64 `json:"truncated"`
	Bytes         int64  `json:"bytes"`
}

type Status struct {
	Enabled  bool      `json:"enabled"`
	Sessions []Session `json:"sessions"`
	Quota    int64     `json:"quota"`
	Used     int64     `json:"used"`
}

type Manager struct {
	mu          sync.Mutex
	db          *sql.DB
	dir, binary string
	quota       int64
	catalog     map[string]Session
	active      string
	cancel      func(string)
	closing     bool
	background  chan struct{}
	wg          sync.WaitGroup
}

func Open(dir, binary string, quotaMiB int) (*Manager, error) {
	if quotaMiB < DefaultQuotaMiB || quotaMiB > 1048576 {
		return nil, errors.New("квота захвата должна быть от 512 до 1048576 МиБ")
	}
	if err := validateBinary(binary); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("для захвата нужен закрытый каталог с правами 0700")
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "catalog.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	m := &Manager{db: db, dir: dir, binary: binary, quota: int64(quotaMiB) << 20, catalog: map[string]Session{}, background: make(chan struct{})}
	if err = m.load(); err != nil {
		db.Close()
		return nil, err
	}
	m.wg.Go(m.sweep)
	return m, nil
}

func (m *Manager) load() error {
	if _, err := m.db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
 CREATE TABLE IF NOT EXISTS captures(id TEXT PRIMARY KEY, body BLOB NOT NULL);`); err != nil {
		return err
	}
	rows, err := m.db.Query("SELECT id,body FROM captures")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var body []byte
		var s Session
		if err := rows.Scan(&id, &body); err != nil {
			return err
		}
		if err := json.Unmarshal(body, &s); err != nil {
			return err
		}
		if !idPattern.MatchString(id) || id != s.ID {
			return errors.New("некорректный ID в каталоге захвата")
		}
		m.catalog[id] = s
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, s := range m.catalog {
		interrupted := s.State == "running"
		if interrupted {
			s.State, s.Reason = "incomplete", "restart"
			now := time.Now().UTC()
			s.End = &now
			s.Expires = now.Add(time.Duration(s.Config.RetentionHours) * time.Hour)
		}
		if !interrupted && (s.Config.RotateFiles == 0 || s.State != "incomplete") {
			continue
		}
		var recoveryErr error
		if s.Config.RotateFiles > 0 {
			recoveryErr = m.recoverRotation(&s)
		} else {
			recoveryErr = m.publish(&s, true)
		}
		if recoveryErr != nil && s.Error == "" {
			s.Error = recoveryErr.Error()
		}
		if err := m.save(s); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if rotatedName.MatchString(entry.Name()) {
			if err := m.removeOrphanSegment(entry.Name()); err != nil {
				return err
			}
			continue
		}
		id, isPart := strings.CutSuffix(entry.Name(), ".part")
		if !isPart || !idPattern.MatchString(id) {
			continue
		}
		if _, ok := m.catalog[id]; !ok {
			if err := os.Remove(m.path(id, ".part")); err != nil {
				return err
			}
		}
	}
	return m.expire()
}

func (m *Manager) save(s Session) error {
	if err := m.persist(s); err != nil {
		return err
	}
	m.catalog[s.ID] = s
	return nil
}

func (m *Manager) persist(s Session) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = m.db.Exec("INSERT INTO captures(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", s.ID, body)
	return err
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := Status{Enabled: true, Sessions: make([]Session, 0, len(m.catalog)), Quota: m.quota}
	for _, s := range m.catalog {
		out.Sessions = append(out.Sessions, s)
		out.Used += s.Bytes
	}
	sort.Slice(out.Sessions, func(i, j int) bool { return out.Sessions[i].Start.After(out.Sessions[j].Start) })
	return out
}

func (m *Manager) Start(id string, c Config) (Session, error) {
	var zero Session
	if !idPattern.MatchString(id) {
		return zero, errors.New("некорректный ID сессии")
	}
	filter, err := c.Filter()
	if err != nil {
		return zero, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.active != "" {
		return zero, ErrBusy
	}
	if _, exists := m.catalog[id]; exists {
		return zero, ErrBusy
	}
	if err = m.expire(); err != nil {
		return zero, err
	}
	maxBytes := int64(c.MaxMiB) << 20
	reserved := maxBytes * int64(max(1, c.RotateFiles))
	used := int64(0)
	for _, s := range m.catalog {
		used += s.Bytes
	}
	if len(m.catalog) >= maxSessions || used+reserved > m.quota {
		return zero, ErrQuota
	}
	if err = spaceAvailable(m.dir, reserved); err != nil {
		return zero, err
	}
	path := m.path(id, ".part")
	if c.RotateFiles > 0 {
		path = m.segmentPath(id, 1, ".part")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return zero, err
	}
	cleanup := func() { file.Close(); _ = os.Remove(file.Name()) }
	reader, backend, fallback, err := openSource(m.binary, c, filter)
	if err != nil {
		cleanup()
		return zero, err
	}
	now := time.Now().UTC()
	s := Session{ID: id, Config: c, Filter: filter, State: "running", Backend: backend, Fallback: fallback, Start: now}
	if err = m.save(s); err != nil {
		reader.close()
		cleanup()
		return zero, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	m.active = id
	m.cancel = func(reason string) { cancel(errors.New(reason)) }
	m.wg.Go(func() { m.run(ctx, s, file, reader, maxBytes) })
	return s, nil
}

func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.catalog[id]; !ok {
		return ErrMissing
	}
	if m.active == id {
		m.cancel("manual")
	}
	return nil
}

func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.catalog[id]; !ok {
		return ErrMissing
	}
	if m.active == id {
		return ErrActive
	}
	return m.remove(id)
}

func (m *Manager) remove(id string) error {
	for _, segment := range m.catalog[id].Segments {
		if err := removeCaptureFile(m.segmentPath(id, segment.Number, ".pcap")); err != nil {
			return err
		}
	}
	for _, suffix := range []string{".pcap", ".part"} {
		if err := removeCaptureFile(m.path(id, suffix)); err != nil {
			return err
		}
	}
	if m.catalog[id].Config.RotateFiles > 0 {
		next := m.catalog[id].nextSegment()
		for _, number := range []int{next, next + 1} {
			for _, suffix := range []string{".pcap", ".part"} {
				if err := removeCaptureFile(m.segmentPath(id, number, suffix)); err != nil {
					return err
				}
			}
		}
	}
	if _, err := m.db.Exec("DELETE FROM captures WHERE id=?", id); err != nil {
		return err
	}
	delete(m.catalog, id)
	return nil
}

func (m *Manager) File(id string) (*os.File, Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.catalog[id]
	if !ok || m.active != id && s.SHA256 == "" {
		return nil, s, ErrMissing
	}
	if m.active == id {
		return nil, s, ErrActive
	}
	f, err := os.Open(m.path(id, ".pcap"))
	return f, s, err
}

func (m *Manager) path(id, suffix string) string { return filepath.Join(m.dir, id+suffix) }

func (m *Manager) expire() error {
	for id, s := range m.catalog {
		if id != m.active && !s.Expires.IsZero() && time.Now().After(s.Expires) {
			if err := m.remove(id); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) sweep() {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-m.background:
			return
		case <-timer.C:
			m.mu.Lock()
			if err := m.expire(); err != nil {
				fmt.Fprintf(os.Stderr, "capture expiry: %v\n", err)
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closing = true
	close(m.background)
	if m.cancel != nil {
		m.cancel("shutdown")
	}
	m.mu.Unlock()
	m.wg.Wait()
	return m.db.Close()
}

func (m *Manager) run(ctx context.Context, s Session, file *os.File, reader source, maxBytes int64) {
	timer := time.AfterFunc(time.Duration(s.Config.Seconds)*time.Second, func() { m.stopActive(s.ID, "duration") })
	defer timer.Stop()
	watcher := context.AfterFunc(ctx, reader.stop)
	defer watcher()
	var captureErr error
	var rotation *rotationWriter
	if s.Config.RotateFiles > 0 {
		rotation = &rotationWriter{manager: m, session: &s, file: file}
		captureErr = rotation.write(reader, maxBytes)
	} else {
		captureErr = m.write(&s, file, reader, maxBytes)
	}
	dropped, closeErr := reader.close()
	s.Dropped = dropped
	captureErr = errors.Join(captureErr, closeErr)
	if rotation != nil {
		captureErr = errors.Join(captureErr, rotation.finish(captureErr != nil))
	} else {
		if err := file.Sync(); captureErr == nil {
			captureErr = err
		}
		if err := file.Close(); captureErr == nil {
			captureErr = err
		}
	}
	if cause := context.Cause(ctx); cause != nil && s.Reason == "" {
		s.Reason = cause.Error()
	}
	if s.Reason == "" && captureErr == nil {
		captureErr = errors.New("источник захвата завершился раньше срока")
	}
	s.State = "complete"
	if captureErr != nil || s.Dropped != nil && *s.Dropped > 0 || s.Truncated > 0 && s.Config.Snaplen == 0 {
		s.State = "incomplete"
		if captureErr != nil {
			s.Error = captureErr.Error()
		}
	}
	if rotation == nil {
		if err := m.publish(&s, captureErr != nil); err != nil {
			s.State = "incomplete"
			if s.Error == "" {
				s.Error = err.Error()
			}
		}
	}
	now := time.Now().UTC()
	s.End = &now
	s.Expires = now.Add(time.Duration(s.Config.RetentionHours) * time.Hour)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.save(s); err != nil {
		fmt.Fprintf(os.Stderr, "capture metadata: %v\n", err)
		m.catalog[s.ID] = s
	}
	m.active, m.cancel = "", nil
}

func (m *Manager) stopActive(id, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == id {
		m.cancel(reason)
	}
}

func (m *Manager) write(s *Session, file *os.File, reader source, maxBytes int64) error {
	snaplen, linkType, err := reader.header()
	if err != nil {
		return err
	}
	buffer := bufio.NewWriterSize(file, 256<<10)
	writer := pcapgo.NewWriterNanos(buffer)
	if err = writer.WriteFileHeader(snaplen, linkType); err != nil {
		return err
	}
	s.Bytes = 24
	if err = buffer.Flush(); err != nil {
		return err
	}
	var last time.Time
	for {
		data, ci, readErr := reader.next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.Join(readErr, buffer.Flush())
		}
		if s.Bytes+16+int64(len(data)) > maxBytes {
			s.Reason = "size"
			break
		}
		if err = writer.WritePacket(ci, data); err != nil {
			return err
		}
		s.addPacket(ci.Length, ci.CaptureLength)
		if s.Config.MaxPackets > 0 && s.Packets == uint64(s.Config.MaxPackets) {
			s.Reason = "packets"
			break
		}
		if time.Since(last) >= time.Second {
			if err = buffer.Flush(); err != nil {
				return err
			}
			m.mu.Lock()
			m.catalog[s.ID] = *s
			m.mu.Unlock()
			last = time.Now()
		}
	}
	return buffer.Flush()
}

func (s *captureStats) addPacket(original, captured int) {
	s.Packets++
	s.OriginalBytes += uint64(original)
	s.CapturedBytes += uint64(captured)
	s.Bytes += 16 + int64(captured)
	if captured < original {
		s.Truncated++
	}
}

func (m *Manager) publish(s *Session, recover bool) error {
	part := m.path(s.ID, ".part")
	final := m.path(s.ID, ".pcap")
	if recover {
		if err := recoverFile(part, &s.captureStats); errors.Is(err, os.ErrNotExist) {
			if err = recoverFile(final, &s.captureStats); err != nil {
				return err
			}
			part = final
		} else if err != nil {
			if s.Bytes == 0 {
				_ = os.Remove(part)
			}
			return err
		}
	}
	if s.Bytes < 24 {
		_ = os.Remove(part)
		return errors.New("источник не записал заголовок PCAP")
	}
	f, err := os.Open(part)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, f)
	f.Close()
	if err != nil {
		return err
	}
	if n != s.Bytes {
		return errors.New("размер файла захвата отличается от каталога")
	}
	if part != final {
		if err = os.Rename(part, final); err != nil {
			return err
		}
	}
	if err = m.syncDir(); err != nil {
		return err
	}
	s.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func (m *Manager) syncDir() error {
	dir, err := os.Open(m.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func recoverFile(path string, s *captureStats) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	s.Packets, s.Bytes, s.CapturedBytes, s.OriginalBytes, s.Truncated = 0, 0, 0, 0, 0
	if err != nil {
		return err
	}
	s.Bytes = 24
	for {
		_, ci, err := reader.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
		s.addPacket(ci.Length, ci.CaptureLength)
	}
	if err = f.Truncate(s.Bytes); err != nil {
		return err
	}
	return f.Sync()
}
