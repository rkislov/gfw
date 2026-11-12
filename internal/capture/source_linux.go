//go:build linux

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func validateBinary(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("нужен абсолютный путь к tcpdump")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("tcpdump должен принадлежать root и быть защищён от записи другими пользователями")
	}
	return nil
}

func spaceAvailable(dir string, size int64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return err
	}
	if stat.Bavail < uint64((size+(128<<20))/int64(stat.Bsize)+1) {
		return errors.New("на разделе захвата недостаточно места с учётом резерва 128 МиБ")
	}
	return nil
}

func openSource(binary string, c Config, filter string) (source, string, string, error) {
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, "", "", errors.New("интерфейс недоступен или выключен")
	}
	var fallback string
	if c.Backend == "xdp" || c.Backend == "xdp-generic" || c.Backend == "auto" && c.Direction == "in" {
		s, err := openXDP(binary, c, filter, iface)
		if err == nil {
			return s, s.backend, "", nil
		}
		if c.Backend != "auto" {
			return nil, "", "", err
		}
		fallback = err.Error()
	}
	s, err := openPacket(binary, c, filter)
	return s, "packet", fallback, err
}

type packetSource struct {
	cmd      *exec.Cmd
	pipe     *os.File
	reader   *pcapgo.Reader
	stderr   bytes.Buffer
	done     chan struct{}
	waitErr  error
	stopping sync.Once
}

func openPacket(binary string, c Config, filter string) (*packetSource, error) {
	args := []string{"-nn", "-p", "-i", c.Interface, "-Q", c.Direction, "-s", strconv.Itoa(c.effectiveSnaplen())}
	if filter != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, append(append([]string{}, args...), "-d", "--", filter)...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("libpcap отклонил фильтр: %.300s", strings.TrimSpace(string(output)))
		}
	}
	// Packet-buffered output (-U) does not flush an unread libpcap capture
	// block. Immediate mode makes packets readable before a normal stop.
	// Allow more room for bursts because immediate mode delivers smaller batches.
	args = append(args, "--immediate-mode", "-Z", "gfw-capture", "-B", "16384", "-U", "-w", "-", "--")
	if filter != "" {
		args = append(args, filter)
	}
	pipe, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	s := &packetSource{cmd: exec.Command(binary, args...), pipe: pipe, done: make(chan struct{})}
	s.cmd.Env = append(os.Environ(), "LC_ALL=C")
	s.cmd.Stdout, s.cmd.Stderr = writer, &s.stderr
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = s.cmd.Start(); err != nil {
		pipe.Close()
		return nil, err
	}
	go func() {
		s.waitErr = s.cmd.Wait()
		close(s.done)
	}()
	return s, nil
}

func (s *packetSource) header() (uint32, layers.LinkType, error) {
	r, err := pcapgo.NewReader(s.pipe)
	if err != nil {
		return 0, 0, err
	}
	s.reader = r
	return r.Snaplen(), r.LinkType(), nil
}

func (s *packetSource) next() ([]byte, gopacket.CaptureInfo, error) {
	return s.reader.ZeroCopyReadPacketData()
}

func (s *packetSource) stop() {
	s.stopping.Do(func() {
		_ = s.cmd.Process.Signal(os.Interrupt)
		go func() {
			select {
			case <-s.done:
			case <-time.After(2 * time.Second):
				_ = s.cmd.Process.Kill()
			}
		}()
	})
}

var droppedPattern = regexp.MustCompile(`(?m)^([0-9]+) packets? dropped by kernel`)

func (s *packetSource) close() (*uint64, error) {
	s.stop()
	_, _ = io.Copy(io.Discard, s.pipe)
	_ = s.pipe.Close()
	<-s.done
	var dropped *uint64
	if match := droppedPattern.FindStringSubmatch(s.stderr.String()); match != nil {
		n, err := strconv.ParseUint(match[1], 10, 64)
		if err == nil {
			dropped = &n
		}
	}
	if s.waitErr != nil {
		return dropped, fmt.Errorf("tcpdump: %.300s (%w)", strings.TrimSpace(s.stderr.String()), s.waitErr)
	}
	return dropped, nil
}
