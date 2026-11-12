package capture

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type Segment struct {
	Number int       `json:"number"`
	End    time.Time `json:"end"`
	SHA256 string    `json:"sha256"`
	captureStats
}

var rotatedName = regexp.MustCompile(`^([a-f0-9]{32})\.([1-9][0-9]*)\.(pcap|part)$`)

func (m *Manager) segmentPath(id string, number int, suffix string) string {
	return m.path(id, "."+strconv.Itoa(number)+suffix)
}

func (s Session) nextSegment() int {
	if n := len(s.Segments); n > 0 {
		return s.Segments[n-1].Number + 1
	}
	return s.RotatedOut + 1
}

func (m *Manager) SegmentFile(id string, number int) (*os.File, Segment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session := m.catalog[id]
	for _, segment := range session.Segments {
		if segment.Number == number {
			file, err := os.Open(m.segmentPath(id, number, ".pcap"))
			if errors.Is(err, os.ErrNotExist) {
				err = ErrMissing
			}
			return file, segment, err
		}
	}
	return nil, Segment{}, ErrMissing
}

func removeCaptureFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *Manager) removeOrphanSegment(name string) error {
	parts := rotatedName.FindStringSubmatch(name)
	s := m.catalog[parts[1]]
	if s.Config.RotateFiles > 0 && s.State == "incomplete" {
		if next := s.nextSegment(); strconv.Itoa(next) == parts[2] || strconv.Itoa(next+1) == parts[2] {
			return nil
		}
	}
	if parts[3] == "pcap" {
		for _, segment := range s.Segments {
			if strconv.Itoa(segment.Number) == parts[2] {
				return nil
			}
		}
	}
	return removeCaptureFile(m.path("", name))
}

func (s *Session) appendSegment(segment Segment) {
	// Status snapshots may still be in use by an HTTP encoder.
	s.Segments = append(slices.Clone(s.Segments), segment)
}

func (m *Manager) recoverRotation(s *Session) error {
	// A rollover can leave the sealing file and the new active file uncommitted.
	next := s.nextSegment()
	if err := m.recoverSegment(s, next); err != nil {
		return err
	}
	return m.recoverSegment(s, next+1)
}

func (m *Manager) recoverSegment(s *Session, number int) error {
	part := m.segmentPath(s.ID, number, ".part")
	final := m.segmentPath(s.ID, number, ".pcap")
	path := part
	if _, err := os.Stat(part); errors.Is(err, os.ErrNotExist) {
		path = final
	} else if err != nil {
		return err
	}
	var segment Segment
	if err := recoverFile(path, &segment.captureStats); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return removeCaptureFile(path)
	} else if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if path != final {
		if err = os.Rename(path, final); err != nil {
			return err
		}
	}
	if err = m.syncDir(); err != nil {
		return err
	}
	segment.Number, segment.End, segment.SHA256 = number, time.Now().UTC(), hex.EncodeToString(hash.Sum(nil))
	s.Packets += segment.Packets
	s.Bytes += segment.Bytes
	s.CapturedBytes += segment.CapturedBytes
	s.OriginalBytes += segment.OriginalBytes
	s.Truncated += segment.Truncated
	s.appendSegment(segment)
	return nil
}

type sealResult struct {
	segment Segment
	err     error
}

type rotationWriter struct {
	manager  *Manager
	session  *Session
	file     *os.File
	buffer   *bufio.Writer
	writer   *pcapgo.Writer
	hash     hash.Hash
	segment  Segment
	snaplen  uint32
	linkType layers.LinkType
	pending  <-chan sealResult
}

func (r *rotationWriter) header(number int) error {
	r.segment = Segment{Number: number}
	r.hash = sha256.New()
	r.buffer = bufio.NewWriterSize(io.MultiWriter(r.file, r.hash), 256<<10)
	r.writer = pcapgo.NewWriterNanos(r.buffer)
	if err := r.writer.WriteFileHeader(r.snaplen, r.linkType); err != nil {
		return err
	}
	r.segment.Bytes = 24
	r.session.Bytes += 24
	return r.buffer.Flush()
}

func (r *rotationWriter) write(reader source, maxBytes int64) error {
	var err error
	r.snaplen, r.linkType, err = reader.header()
	if err != nil {
		return err
	}
	if err = r.header(r.session.nextSegment()); err != nil {
		return err
	}
	var last time.Time
	for {
		data, ci, err := reader.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.segment.Bytes+16+int64(len(data)) > maxBytes {
			if err = r.rotate(maxBytes); err != nil {
				return err
			}
		}
		if err = r.writer.WritePacket(ci, data); err != nil {
			return err
		}
		r.segment.addPacket(ci.Length, ci.CaptureLength)
		r.session.addPacket(ci.Length, ci.CaptureLength)
		if r.session.Config.MaxPackets > 0 && r.session.Packets == uint64(r.session.Config.MaxPackets) {
			r.session.Reason = "packets"
			return nil
		}
		if time.Since(last) >= time.Second {
			if err = r.settle(false); err != nil {
				return err
			}
			if err = r.buffer.Flush(); err != nil {
				return err
			}
			r.manager.mu.Lock()
			r.manager.catalog[r.session.ID] = *r.session
			r.manager.mu.Unlock()
			last = time.Now()
		}
	}
}

func (r *rotationWriter) rotate(maxBytes int64) error {
	if err := r.settle(true); err != nil {
		return err
	}
	if err := r.buffer.Flush(); err != nil {
		return err
	}
	m, s := r.manager, r.session
	if len(s.Segments)+2 > s.Config.RotateFiles {
		m.mu.Lock()
		err := m.evictSegment(s, r.segment.captureStats)
		m.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := spaceAvailable(m.dir, maxBytes); err != nil {
		return err
	}
	snapshot, segment, file := *s, r.segment, r.file
	segment.SHA256 = hex.EncodeToString(r.hash.Sum(nil))
	done := make(chan sealResult, 1)
	r.pending = done
	go func(file *os.File) {
		err := m.sealFile(file, snapshot.ID, &segment)
		if err == nil {
			snapshot.appendSegment(segment)
			err = m.persist(snapshot)
		}
		done <- sealResult{segment: segment, err: err}
	}(file)

	next := r.segment.Number + 1
	r.file = nil
	path := m.segmentPath(s.ID, next, ".part")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	r.file = file
	return r.header(next)
}

func (r *rotationWriter) settle(block bool) error {
	if r.pending == nil {
		return nil
	}
	var result sealResult
	if block {
		result = <-r.pending
	} else {
		select {
		case result = <-r.pending:
		default:
			return nil
		}
	}
	r.pending = nil
	if result.err == nil {
		r.session.appendSegment(result.segment)
		return nil
	}
	r.session.subtract(result.segment.captureStats)
	return errors.Join(result.err, r.manager.recoverSegment(r.session, result.segment.Number))
}

func (s *captureStats) subtract(part captureStats) {
	s.Packets -= part.Packets
	s.Bytes -= part.Bytes
	s.CapturedBytes -= part.CapturedBytes
	s.OriginalBytes -= part.OriginalBytes
	s.Truncated -= part.Truncated
}

// evictSegment is called with the catalog lock held. The active file stays
// outside the persisted snapshot so it can be recovered exactly once.
func (m *Manager) evictSegment(s *Session, active captureStats) error {
	prior := *s
	old := s.Segments[0]
	s.Segments = s.Segments[1:]
	s.RotatedOut++
	s.Bytes -= old.Bytes
	snapshot := *s
	snapshot.subtract(active)
	if err := m.persist(snapshot); err != nil {
		*s = prior
		return err
	}
	if err := removeCaptureFile(m.segmentPath(s.ID, old.Number, ".pcap")); err != nil {
		*s = prior
		prior.subtract(active)
		return errors.Join(err, m.persist(prior))
	}
	m.catalog[s.ID] = *s
	return nil
}

func (m *Manager) sealFile(file *os.File, id string, segment *Segment) error {
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), m.segmentPath(id, segment.Number, ".pcap")); err != nil {
		return err
	}
	if err := m.syncDir(); err != nil {
		return err
	}
	segment.End = time.Now().UTC()
	return nil
}

func (r *rotationWriter) finish(recover bool) error {
	pendingErr := r.settle(true)
	if r.file == nil {
		return pendingErr
	}
	m, s := r.manager, r.session
	var err error
	if r.buffer != nil {
		err = r.buffer.Flush()
	}
	if pendingErr != nil && s.nextSegment() < r.segment.Number {
		s.subtract(r.segment.captureStats)
		return errors.Join(pendingErr, err, r.file.Close())
	}
	if !recover && err == nil && r.segment.Bytes >= 24 {
		r.segment.SHA256 = hex.EncodeToString(r.hash.Sum(nil))
		err = m.sealFile(r.file, s.ID, &r.segment)
		if err == nil {
			s.appendSegment(r.segment)
			return pendingErr
		}
	} else {
		err = errors.Join(err, r.file.Close())
	}
	// Recount the last file from complete records after a write failure.
	s.subtract(r.segment.captureStats)
	number := r.segment.Number
	if number == 0 {
		number = s.nextSegment()
	}
	if recoverErr := m.recoverSegment(s, number); recoverErr != nil {
		err = errors.Join(err, fmt.Errorf("восстановление сегмента: %w", recoverErr))
	}
	return errors.Join(pendingErr, err)
}
