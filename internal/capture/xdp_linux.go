//go:build linux

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cloudflare/cbpfc"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type xdpSource struct {
	attached      link.Link
	reader        *ringbuf.Reader
	events, drops *ebpf.Map
	record        ringbuf.Record
	offset        int64
	snaplen       uint32
	backend       string
	stopping      sync.Once
	stopErr       error
}

const xdpMaxFrame = 3072

func openXDP(tcpdump string, c Config, expression string, iface *net.Interface) (_ *xdpSource, err error) {
	if len(iface.HardwareAddr) != 6 || iface.MTU > 3000 {
		return nil, errors.New("XDP-захват доступен на Ethernet с MTU до 3000")
	}
	current, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, err
	}
	if xdp := current.Attrs().Xdp; xdp != nil && xdp.Attached {
		return nil, errors.New("на интерфейсе уже работает XDP-программа")
	}
	filter, err := xdpFilter(tcpdump, expression, c.effectiveSnaplen())
	if err != nil {
		return nil, err
	}
	var boot unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &boot); err != nil {
		return nil, err
	}
	s := &xdpSource{offset: time.Now().UnixNano() - boot.Nano(), snaplen: uint32(c.effectiveSnaplen()), backend: "xdp"}
	defer func() {
		if err == nil {
			return
		}
		if s.reader != nil {
			_ = s.reader.Close()
		}
		if s.drops != nil {
			_ = s.drops.Close()
		}
		if s.events != nil {
			_ = s.events.Close()
		}
	}()
	s.events, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4 << 20})
	if err != nil {
		return nil, fmt.Errorf("XDP недоступен: %w", err)
	}
	s.drops, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	scratch, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16 + xdpMaxFrame, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	defer scratch.Close()
	s.reader, err = ringbuf.NewReader(s.events)
	if err != nil {
		return nil, fmt.Errorf("буфер XDP недоступен: %w", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "gfw_capture", Type: ebpf.XDP, AttachType: ebpf.AttachXDP,
		License: "GPL", Instructions: xdpProgram(filter, c.effectiveSnaplen(), s.events.FD(), s.drops.FD(), scratch.FD())})
	if err != nil {
		return nil, fmt.Errorf("ядро отклонило программу захвата XDP: %w", err)
	}
	defer prog.Close()
	mode := link.XDPDriverMode
	if c.Backend == "xdp-generic" {
		mode, s.backend = link.XDPGenericMode, "xdp-generic"
	}
	s.attached, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: mode})
	if err != nil {
		return nil, fmt.Errorf("не удалось подключить %s на %s: %w", s.backend, iface.Name, err)
	}
	return s, nil
}

func xdpFilter(tcpdump, expression string, snaplen int) (asm.Instructions, error) {
	if expression == "" {
		return nil, nil
	}
	var pcap bytes.Buffer
	if err := pcapgo.NewWriter(&pcap).WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tcpdump, "-nn", "-r", "-", "-ddd", "--", expression)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = &pcap
	output, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("libpcap отклонил фильтр: %.300s", strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	n, err := strconv.Atoi(lines[0])
	if err != nil || n < 1 || n > 4096 || len(lines) != n+1 {
		return nil, errors.New("некорректная программа libpcap")
	}
	raw := make([]bpf.RawInstruction, n)
	for i, line := range lines[1:] {
		v := &raw[i]
		if _, err = fmt.Sscan(line, &v.Op, &v.Jt, &v.Jf, &v.K); err != nil {
			return nil, err
		}
	}
	instructions, ok := bpf.Disassemble(raw)
	if !ok {
		return nil, errors.New("фильтр libpcap содержит инструкции, недоступные в XDP")
	}
	return cbpfc.ToEBPF(instructions, cbpfc.EBPFOpts{
		PacketStart: asm.R2, PacketEnd: asm.R3, Result: asm.R0, ResultLabel: "filtered",
		Working: [4]asm.Register{asm.R0, asm.R4, asm.R5, asm.R9}, StackOffset: 24, LabelPrefix: "filter",
	})
}

// The program copies matching ingress frames and returns XDP_PASS on every path.
func xdpProgram(filter asm.Instructions, snaplen, eventFD, dropFD, scratchFD int) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
	}
	if len(filter) > 0 {
		ins = append(ins, filter...)
		ins = append(ins, asm.JEq.Imm(asm.R0, 0, "pass").WithSymbol("filtered"))
	}
	ins = append(ins,
		asm.Mov.Reg(asm.R7, asm.R3), asm.Sub.Reg(asm.R7, asm.R2),
		asm.Mov.Reg32(asm.R8, asm.R7),
		asm.JLE.Imm(asm.R8, int32(min(snaplen, xdpMaxFrame)), "scratch"),
		asm.Mov.Imm(asm.R8, int32(min(snaplen, xdpMaxFrame))),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word).WithSymbol("scratch"),
		asm.LoadMapPtr(asm.R1, scratchFD),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -20), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "lost"), asm.Mov.Reg(asm.R9, asm.R0),
		asm.StoreMem(asm.R9, 0, asm.R7, asm.Word), asm.StoreMem(asm.R9, 4, asm.R8, asm.Word),
		asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.R9, 8, asm.R0, asm.DWord),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		asm.Mov.Imm(asm.R5, 0),
		// Copy complete words first. Explicit bounds protect both packet and map value.
		asm.Mov.Reg(asm.R4, asm.R5).WithSymbol("word"),
		asm.Add.Imm(asm.R4, 8), asm.JGT.Reg(asm.R4, asm.R8, "tail"),
		asm.JGT.Imm(asm.R5, xdpMaxFrame-8, "lost"),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word), asm.Add.Reg(asm.R2, asm.R5),
		asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 8), asm.JGT.Reg(asm.R4, asm.R3, "lost"),
		asm.LoadMem(asm.R1, asm.R2, 0, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.R9), asm.Add.Reg(asm.R4, asm.R5), asm.StoreMem(asm.R4, 16, asm.R1, asm.DWord),
		asm.Add.Imm(asm.R5, 8), asm.Ja.Label("word"),
		asm.JGE.Reg(asm.R5, asm.R8, "output").WithSymbol("tail"),
	)
	// At most seven bytes remain after the word loop. Unroll the tail for older verifiers.
	for range 7 {
		ins = append(ins,
			asm.JGE.Reg(asm.R5, asm.R8, "output"), asm.JGE.Imm(asm.R5, xdpMaxFrame, "lost"),
			asm.LoadMem(asm.R2, asm.R6, 0, asm.Word), asm.Add.Reg(asm.R2, asm.R5),
			asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 1), asm.JGT.Reg(asm.R4, asm.R3, "lost"),
			asm.LoadMem(asm.R1, asm.R2, 0, asm.Byte),
			asm.Mov.Reg(asm.R4, asm.R9), asm.Add.Reg(asm.R4, asm.R5), asm.StoreMem(asm.R4, 16, asm.R1, asm.Byte),
			asm.Add.Imm(asm.R5, 1),
		)
	}
	return append(ins,
		asm.LoadMapPtr(asm.R1, eventFD).WithSymbol("output"),
		asm.Mov.Reg(asm.R2, asm.R9), asm.Mov.Reg(asm.R3, asm.R8), asm.Add.Imm(asm.R3, 16), asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(), asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word).WithSymbol("lost"), asm.LoadMapPtr(asm.R1, dropFD),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -20), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("pass"), asm.Return(),
	)
}

func (s *xdpSource) header() (uint32, layers.LinkType, error) {
	return s.snaplen, layers.LinkTypeEthernet, nil
}

func (s *xdpSource) next() ([]byte, gopacket.CaptureInfo, error) {
	for {
		err := s.reader.ReadInto(&s.record)
		if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, os.ErrClosed) {
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		data := s.record.RawSample
		if len(data) < 16 {
			return nil, gopacket.CaptureInfo{}, errors.New("неполная запись XDP")
		}
		original := int(binary.NativeEndian.Uint32(data))
		captured := int(binary.NativeEndian.Uint32(data[4:]))
		if captured > len(data)-16 || captured > original {
			return nil, gopacket.CaptureInfo{}, errors.New("неполный пакет XDP")
		}
		ts := int64(binary.NativeEndian.Uint64(data[8:]))
		return data[16 : 16+captured], gopacket.CaptureInfo{Timestamp: time.Unix(0, ts+s.offset), CaptureLength: captured, Length: original}, nil
	}
}

func (s *xdpSource) stop() {
	s.stopping.Do(func() {
		s.stopErr = s.attached.Close()
		if err := s.reader.Flush(); err != nil {
			_ = s.reader.Close()
		}
	})
}

func (s *xdpSource) close() (*uint64, error) {
	s.stop()
	_ = s.reader.Close()
	var perCPU []uint64
	var total uint64
	if err := s.drops.Lookup(uint32(0), &perCPU); err == nil {
		for _, n := range perCPU {
			total += n
		}
	}
	_ = s.drops.Close()
	_ = s.events.Close()
	return &total, s.stopErr
}
