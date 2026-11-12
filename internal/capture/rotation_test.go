package capture

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRotationRecoveryKeepsSealedAndTruncatesPartialSegment(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", dir+"/catalog.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := &Manager{db: db, dir: dir, catalog: map[string]Session{}}
	if err = m.load(); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	s := Session{ID: id, State: "running", Config: Config{RotateFiles: 3, RetentionHours: 1}}
	part, err := os.OpenFile(m.segmentPath(id, 1, ".part"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	writer := rotationWriter{manager: m, session: &s, file: part, snaplen: FullSnaplen, linkType: layers.LinkTypeEthernet}
	if err = writer.header(1); err != nil {
		t.Fatal(err)
	}
	if err = writer.finish(false); err != nil {
		t.Fatal(err)
	}
	if err = m.save(s); err != nil {
		t.Fatal(err)
	}

	// The second file was renamed before its metadata commit.
	part, err = os.OpenFile(m.segmentPath(id, 2, ".part"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	writer.file = part
	if err = writer.header(2); err != nil {
		t.Fatal(err)
	}
	if err = writer.finish(false); err != nil {
		t.Fatal(err)
	}
	// The next file can contain complete records followed by a torn record header.
	part, err = os.OpenFile(m.segmentPath(id, 3, ".part"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	pcap := pcapgo.NewWriterNanos(part)
	if err = pcap.WriteFileHeader(FullSnaplen, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 64)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(packet), Length: len(packet)}
	if err = pcap.WritePacket(ci, packet); err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err = part.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := &Manager{db: db, dir: dir, catalog: map[string]Session{}}
	if err = reopened.load(); err != nil {
		t.Fatal(err)
	}
	got := reopened.catalog[id]
	if got.State != "incomplete" || got.Reason != "restart" || got.Packets != 1 || got.Bytes != 152 ||
		len(got.Segments) != 3 || got.Segments[0].SHA256 != s.Segments[0].SHA256 {
		t.Fatalf("unexpected recovered session: %+v", got)
	}
	file, segment, err := reopened.SegmentFile(id, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if segment.Packets != 1 || segment.Bytes != 104 {
		t.Fatalf("unexpected recovered segment: %+v", segment)
	}
}
