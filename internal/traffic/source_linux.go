//go:build linux

package traffic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	conntrackSubsystem = 1
	nflogSubsystem     = 4
)

func (c *Collector) startSources(ctx context.Context) {
	c.sources.Add(2)
	go c.source(ctx, false)
	go c.source(ctx, true)
}

func (c *Collector) source(ctx context.Context, logging bool) {
	defer c.sources.Done()
	for ctx.Err() == nil {
		if err := c.receive(ctx, logging); err != nil && ctx.Err() == nil {
			c.note(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Collector) receive(ctx context.Context, logging bool) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if !logging {
		sa.Groups = 7
	}
	if err = unix.Bind(fd, sa); err != nil {
		return err
	}
	if logging {
		withConntrack := true
		err = bindLog(fd, withConntrack)
		if errors.Is(err, unix.EOPNOTSUPP) {
			withConntrack = false
			err = bindLog(fd, withConntrack)
		}
		if err != nil {
			return fmt.Errorf("NFLOG: %w", err)
		}
		c.nflogConntrack.Store(withConntrack)
		c.nflog.Store(true)
		defer c.nflog.Store(false)
		defer c.nflogConntrack.Store(false)
	} else {
		c.conntrack.Store(true)
		defer c.conntrack.Store(false)
	}
	buffer := make([]byte, 256<<10)
	var logSeq uint32
	seenSeq := false
	var snapshotSeq uint32
	var snapshotPending bool
	var snapshotCount int
	var lastSnapshot, nextSnapshot time.Time
	for ctx.Err() == nil {
		now := time.Now()
		if !logging && !now.Before(nextSnapshot) {
			if snapshotPending {
				c.incompleteSnapshots.Add(1)
			}
			snapshotSeq++
			snapshotCount = 0
			lastSnapshot, nextSnapshot = now, now.Add(5*time.Minute)
			snapshotPending = requestSnapshot(fd, snapshotSeq) == nil
			if !snapshotPending {
				c.incompleteSnapshots.Add(1)
			}
		}
		n, _, flags, addr, e := unix.Recvmsg(fd, buffer, nil, 0)
		if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.ENOBUFS) || flags&unix.MSG_TRUNC != 0 {
			c.lost.Add(1)
			seenSeq = false
			if !logging {
				nextSnapshot = lastSnapshot.Add(30 * time.Second)
			}
			continue
		}
		if e != nil {
			return e
		}
		if sender, ok := addr.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			continue
		}
		messages, e := syscall.ParseNetlinkMessage(buffer[:n])
		if e != nil {
			c.lost.Add(1)
			continue
		}
		for _, m := range messages {
			snapshot := !logging && snapshotPending && m.Header.Seq == snapshotSeq
			if snapshot && (m.Header.Type == unix.NLMSG_DONE || m.Header.Type == unix.NLMSG_ERROR) {
				if snapshotCount > snapshotLimit || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 ||
					m.Header.Type == unix.NLMSG_ERROR || len(m.Data) >= 4 && binary.NativeEndian.Uint32(m.Data) != 0 {
					c.incompleteSnapshots.Add(1)
				}
				snapshotPending = false
				continue
			}
			if len(m.Data) < 4 {
				continue
			}
			subsystem := m.Header.Type >> 8
			attrs := attributes(m.Data[4:])
			at := time.Now().UnixMilli()
			if logging && subsystem == nflogSubsystem && m.Header.Type&255 == 0 {
				if seq := attrs[12]; len(seq) == 4 {
					current := binary.BigEndian.Uint32(seq)
					if seenSeq && current != logSeq+1 {
						c.lost.Add(uint64(current - logSeq - 1))
					}
					seenSeq, logSeq = true, current
				}
				if event, ok := c.parseLog(attrs, at); ok {
					c.enqueue(event)
				}
			} else if !logging && subsystem == conntrackSubsystem {
				kind := "update"
				switch {
				case snapshot:
					snapshotCount++
					if snapshotCount > snapshotLimit {
						continue
					}
					kind = "snapshot"
				case m.Header.Seq != 0:
					continue
				case m.Header.Type&255 == nl.IPCTNL_MSG_CT_NEW:
					if m.Header.Flags&(unix.NLM_F_CREATE|unix.NLM_F_EXCL) != 0 {
						kind = "new"
					}
				case m.Header.Type&255 == nl.IPCTNL_MSG_CT_DELETE:
					kind = "destroy"
				default:
					continue
				}
				event := Event{At: at, Kind: kind}
				if c.fillConntrack(&event, attrs) {
					c.enqueue(event)
				}
			}
		}
	}
	return nil
}

const snapshotLimit = 1024

func requestSnapshot(fd int, sequence uint32) error {
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], conntrackSubsystem<<8|nl.IPCTNL_MSG_CT_GET)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	return unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func bindLog(fd int, withConntrack bool) error {
	mode := []byte{0, 0, 0, 128, 2, 0}
	flags := []byte{0, 1} // Instance sequence.
	if withConntrack {
		flags[1] |= 4
	}
	request := make([]byte, 20)
	binary.NativeEndian.PutUint16(request[4:], nflogSubsystem<<8|1)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:], 1)
	binary.BigEndian.PutUint16(request[18:], Group)
	for _, attr := range []struct {
		kind uint16
		data []byte
	}{{1, []byte{1}}, {2, mode}, {6, flags}} {
		size := 4 + len(attr.data)
		record := make([]byte, (size+3)&^3)
		binary.NativeEndian.PutUint16(record, uint16(size))
		binary.NativeEndian.PutUint16(record[2:], attr.kind)
		copy(record[4:], attr.data)
		request = append(request, record...)
	}
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	for {
		n, _, _, addr, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			return err
		}
		if sender, ok := addr.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			continue
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, m := range messages {
			if m.Header.Seq == 1 && m.Header.Type == unix.NLMSG_ERROR && len(m.Data) >= 4 {
				errno := int32(binary.NativeEndian.Uint32(m.Data))
				if errno == 0 {
					return nil
				}
				return syscall.Errno(-errno)
			}
		}
	}
}

func attributes(b []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b))
		if n < 4 || n > len(b) {
			break
		}
		out[binary.NativeEndian.Uint16(b[2:])&0x3fff] = b[4:n]
		padded := (n + 3) &^ 3
		if padded > len(b) {
			break
		}
		b = b[padded:]
	}
	return out
}

func addrString(b []byte) string {
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return ""
	}
	return ip.String()
}

func u16(b []byte) uint16 {
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func u32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func counter(b []byte) *uint64 {
	if len(b) != 8 {
		return nil
	}
	n := binary.BigEndian.Uint64(b)
	return &n
}

func tuple(b []byte) (src, dst string, sport, dport uint16, proto uint8) {
	t := attributes(b)
	a, p := attributes(t[1]), attributes(t[2])
	src, dst = addrString(a[1]), addrString(a[2])
	if src == "" {
		src, dst = addrString(a[3]), addrString(a[4])
	}
	if len(p[1]) == 1 {
		proto = p[1][0]
	}
	return src, dst, u16(p[2]), u16(p[3]), proto
}

func (c *Collector) fillConntrack(e *Event, a map[uint16][]byte) bool {
	e.Source, e.Destination, e.SourcePort, e.DestinationPort, e.Protocol = tuple(a[nl.CTA_TUPLE_ORIG])
	if e.Source == "" || e.Destination == "" {
		return false
	}
	e.ReplySource, e.ReplyDestination, e.ReplySourcePort, e.ReplyDestinationPort, _ = tuple(a[nl.CTA_TUPLE_REPLY])
	e.Zone = u16(a[nl.CTA_ZONE])
	e.NAT = u32(a[nl.CTA_STATUS])&(1<<4|1<<5) != 0
	orig, reply := attributes(a[nl.CTA_COUNTERS_ORIG]), attributes(a[nl.CTA_COUNTERS_REPLY])
	e.Packets, e.Bytes, e.ReplyPackets, e.ReplyBytes = counter(orig[1]), counter(orig[2]), counter(reply[1]), counter(reply[2])
	if id := a[nl.CTA_ID]; len(id) == 4 {
		value := fmt.Sprintf("%s/%s/%s/%d/%x/%s/%s/%d/%d/%d", c.device, c.boot, c.namespace, e.Zone, id, e.Source, e.Destination, e.SourcePort, e.DestinationPort, e.Protocol)
		sum := sha256.Sum256([]byte(value))
		e.FlowID = hex.EncodeToString(sum[:16])
	}
	return true
}

func (c *Collector) parseLog(a map[uint16][]byte, at int64) (Event, bool) {
	p := strings.Split(strings.TrimRight(string(a[10]), "\x00"), ":")
	if len(p) != 5 || p[0] != "gfw" || p[4] == "" || len(p[4]) > 80 {
		return Event{}, false
	}
	if (p[2] != "input" && p[2] != "output" && p[2] != "forward") || (p[3] != "accept" && p[3] != "drop" && p[3] != "reject") {
		return Event{}, false
	}
	rev, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || rev < 0 {
		return Event{}, false
	}
	e := Event{At: at, Kind: "rule", Revision: rev, Direction: p[2], Action: p[3], Rule: p[4], In: u32(a[4]), Out: u32(a[5])}
	if stamp := a[3]; len(stamp) == 16 {
		e.At = int64(binary.BigEndian.Uint64(stamp))*1000 + int64(binary.BigEndian.Uint64(stamp[8:]))/1000
	}
	if !c.fillConntrack(&e, attributes(a[18])) {
		packetTuple(&e, a[9])
	}
	return e, true
}

func packetTuple(e *Event, b []byte) {
	if len(b) == 0 {
		return
	}
	var off int
	switch {
	case b[0]>>4 == 4 && len(b) >= 20:
		e.Source, e.Destination, e.Protocol = addrString(b[12:16]), addrString(b[16:20]), b[9]
		off = int(b[0]&15) * 4
		if off < 20 || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return
		}
	case b[0]>>4 == 6 && len(b) >= 40:
		e.Source, e.Destination, e.Protocol = addrString(b[8:24]), addrString(b[24:40]), b[6]
		off = 40
		for off+2 <= len(b) {
			next := b[off]
			switch e.Protocol {
			case 0, 43, 60:
				off += (int(b[off+1]) + 1) * 8
			case 51:
				off += (int(b[off+1]) + 2) * 4
			case 44:
				if off+8 > len(b) || binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
					return
				}
				off += 8
			default:
				goto ports
			}
			e.Protocol = next
		}
	default:
		return
	}
ports:
	if off+4 <= len(b) && (e.Protocol == 6 || e.Protocol == 17 || e.Protocol == 132) {
		e.SourcePort, e.DestinationPort = u16(b[off:off+2]), u16(b[off+2:off+4])
	}
}
