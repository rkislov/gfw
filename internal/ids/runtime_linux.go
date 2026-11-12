//go:build linux

package ids

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Runtime struct {
	mu       sync.Mutex
	path     string
	work     string
	uid, gid uint32
	db       *sql.DB
	lock     *os.File
	current  *sensor
	error    string
	dropped  atomic.Uint64
	lastLogs []string
}

type sensor struct {
	cmd       *exec.Cmd
	done      chan struct{}
	stopIO    func()
	dir       string
	config    Config
	links     []int
	queuePeer uint64
	log       *sensorLog
}

type sensorLog struct {
	mu      sync.Mutex
	lines   []string
	partial string
	ready   chan struct{}
	once    sync.Once
}

func newSensorLog() *sensorLog { return &sensorLog{ready: make(chan struct{})} }

func (l *sensorLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, chunk := range strings.SplitAfter(string(p), "\n") {
		line := strings.TrimSuffix(chunk, "\n")
		if len(l.partial) < 768 {
			l.partial += cleanText(line, 768-len(l.partial))
		}
		if !strings.HasSuffix(chunk, "\n") {
			continue
		}
		if strings.Contains(strings.ToLower(l.partial), "engine started") {
			l.once.Do(func() { close(l.ready) })
		}
		if len(l.lines) >= 100 {
			copy(l.lines, l.lines[1:])
			l.lines = l.lines[:99]
		}
		l.lines = append(l.lines, l.partial)
		l.partial = ""
	}
	return len(p), nil
}

func (l *sensorLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.lines...)
}

func NewRuntime(path, work, state string, uid, gid uint32) (*Runtime, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(work) || uid == 0 || gid == 0 {
		return nil, errors.New("IDS needs absolute paths and a dedicated unprivileged user/group")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !fi.Mode().IsRegular() || (fi.Mode().Perm()&0022 != 0 || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) || fi.Mode().Perm()&0111 == 0 {
		return nil, errors.New("Suricata must be a trusted root-owned executable without setuid/setgid")
	}
	if err = os.MkdirAll(work, 0750); err != nil {
		return nil, err
	}
	fi, err = os.Lstat(work)
	if err != nil {
		return nil, err
	}
	st, ok = fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
		return nil, errors.New("IDS runtime directory must be root-owned and protected from writes")
	}
	if err = os.Chown(work, 0, int(gid)); err != nil {
		return nil, err
	}
	if err = os.Chmod(work, 0750); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(work, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Runtime, error) { _ = lock.Close(); return nil, err }
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(errors.New("IDS runtime is owned by another agent"))
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		return fail(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "ids-") {
			if err = os.RemoveAll(filepath.Join(work, entry.Name())); err != nil {
				return fail(err)
			}
		}
	}
	if err = os.MkdirAll(state, 0700); err != nil {
		return fail(err)
	}
	db, err := openEvents(state)
	if err != nil {
		return fail(err)
	}
	return &Runtime{path: path, work: work, db: db, lock: lock, uid: uid, gid: gid}, nil
}

func interfaces(c Config) ([]int, error) {
	var indices []int
	for _, name := range c.Interfaces {
		link, err := net.InterfaceByName(name)
		if err != nil || link.Flags&net.FlagUp == 0 || len(link.HardwareAddr) != 6 {
			return nil, fmt.Errorf("IDS: интерфейс %s должен быть поднятым Ethernet-совместимым интерфейсом", name)
		}
		indices = append(indices, link.Index)
	}
	return indices, nil
}

func (r *Runtime) stage(c Config) (string, error) {
	dir, err := os.MkdirTemp(r.work, "ids-")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	if err = os.Chown(dir, 0, int(r.gid)); err != nil {
		return "", err
	}
	if err = os.Chmod(dir, 0750); err != nil {
		return "", err
	}
	output := filepath.Join(dir, "output")
	if err = os.Mkdir(output, 0700); err != nil {
		return "", err
	}
	if err = os.Chown(output, int(r.uid), int(r.gid)); err != nil {
		return "", err
	}
	files := map[string]string{"suricata.yaml": render(c, dir), "local.rules": c.Rules + "\n"}
	c.FileIOC.AddRules(files)
	for _, name := range []string{"classification.config", "reference.config"} {
		source, err := os.Open(filepath.Join("/etc/gfw/ids", name))
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(source, (1<<20)+1))
		source.Close()
		if err != nil {
			return "", err
		}
		if len(data) > 1<<20 {
			return "", errors.New("Suricata metadata file exceeds 1 MiB")
		}
		files[name] = string(data)
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err = os.WriteFile(path, []byte(content), 0600); err != nil {
			return "", err
		}
		if err = os.Chown(path, 0, int(r.gid)); err != nil {
			return "", err
		}
		if err = os.Chmod(path, 0640); err != nil {
			return "", err
		}
	}
	success = true
	return dir, nil
}

func render(c Config, dir string) string {
	var b strings.Builder
	pendingPackets := 1024
	if c.Inline() {
		// Suricata 8 derives the NFQUEUE limit as four times this value.
		// Leave room for short scheduler stalls while preserving the configured verdict policy.
		pendingPackets = 4096
	}
	fmt.Fprintf(&b, `%%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: %q
    EXTERNAL_NET: "!$HOME_NET"
default-log-dir: %q
default-rule-path: %q
rule-files: [local.rules]
classification-file: %q
reference-config-file: %q
runmode: workers
max-pending-packets: %d
unix-command:
  enabled: no
security:
  lua:
    allow-rules: false
datasets:
  rules:
    allow-absolute-filenames: false
    allow-write: false
stats:
  enabled: no
flow:
  memcap: 32mb
stream:
  inline: %s
  memcap: 32mb
  reassembly:
    memcap: 64mb
    depth: 1mb
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_dgram
      filename: %q
      types:
        - alert:
            metadata: no
            payload: no
            packet: no
`, "["+strings.Join(c.HomeNet, ",")+"]", filepath.Join(dir, "output"), dir, filepath.Join(dir, "classification.config"), filepath.Join(dir, "reference.config"), pendingPackets, yesNo(c.Inline()), filepath.Join(dir, "eve.sock"))
	if c.Inline() {
		fmt.Fprintf(&b, "nfq:\n  mode: accept\n  fail-open: %s\n", yesNo(c.FailurePolicy == "open"))
		return b.String()
	}
	b.WriteString("af-packet:\n")
	for i, name := range c.Interfaces {
		fmt.Fprintf(&b, "  - interface: %q\n    threads: 1\n    cluster-id: %d\n    cluster-type: cluster_flow\n    disable-promisc: yes\n    ring-size: 2048\n", name, 37910+i)
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func readQueue() (*QueueStatus, error) {
	raw, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != strconv.Itoa(QueueNumber) {
			continue
		}
		var q QueueStatus
		for i, value := range map[int]*uint64{1: &q.PortID, 2: &q.Waiting, 5: &q.KernelDropped, 6: &q.UserDropped} {
			n, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return nil, errors.New("Не удалось прочитать состояние NFQUEUE")
			}
			*value = n
		}
		return &q, nil
	}
	return nil, nil
}

func (r *Runtime) command(ctx context.Context, dir string, c Config, capture bool) *exec.Cmd {
	args := []string{"-c", filepath.Join(dir, "suricata.yaml"), "--init-errors-fatal"}
	if capture && c.Inline() {
		args = append(args, "-q", strconv.Itoa(QueueNumber))
	} else if capture {
		args = append(args, "--af-packet")
	} else {
		args = append(args, "-T")
	}
	cmd := exec.CommandContext(ctx, r.path, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LANG=C", "HOME=/nonexistent", "TZ=UTC"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: r.uid, Gid: r.gid, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	if capture && c.Inline() {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_ADMIN}
	} else if capture {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_RAW}
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func (r *Runtime) Prepare(c Config) (Plan, error) {
	p := Preview(c)
	if err := Validate(c); err != nil {
		return p, err
	}
	if !c.Enabled {
		p.Checked, p.CanApply = true, true
		return p, nil
	}
	if _, err := interfaces(c); err != nil {
		return p, err
	}
	dir, err := r.stage(c)
	if err != nil {
		return p, err
	}
	defer os.RemoveAll(dir)
	// Suricata initializes EVE during -T. Create the private socket first.
	sock, err := r.listen(dir)
	if err != nil {
		return p, err
	}
	defer sock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := r.command(ctx, dir, c, false)
	log := newSensorLog()
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Run(); err != nil {
		return p, fmt.Errorf("suricata -T: %w\n%s", err, strings.Join(log.snapshot(), "\n"))
	}
	p.Checked, p.CanApply = true, true
	return p, nil
}

func (r *Runtime) listen(dir string) (*net.UnixConn, error) {
	path := filepath.Join(dir, "eve.sock")
	sock, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(path, 0, int(r.gid)); err == nil {
		err = os.Chmod(path, 0660)
	}
	if err != nil {
		sock.Close()
		return nil, err
	}
	_ = sock.SetReadBuffer(512 << 10)
	return sock, nil
}

func (r *Runtime) collect(sock *net.UnixConn, hash string) func() {
	queue := make(chan Alert, 1024)
	readerDone, writerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(queue)
		buf := make([]byte, 32<<10)
		for {
			n, _, flags, _, err := sock.ReadMsgUnix(buf, nil)
			if err != nil {
				return
			}
			if flags&unix.MSG_TRUNC != 0 {
				r.dropped.Add(1)
				continue
			}
			e, ok := parseAlert(buf[:n], hash)
			if !ok {
				r.dropped.Add(1)
				continue
			}
			select {
			case queue <- e:
			default:
				r.dropped.Add(1)
			}
		}
	}()
	go func() {
		defer close(writerDone)
		timer := time.NewTicker(250 * time.Millisecond)
		defer timer.Stop()
		batch := make([]Alert, 0, 64)
		flush := func() {
			if len(batch) != 0 {
				if err := writeEvents(r.db, batch); err != nil {
					r.dropped.Add(uint64(len(batch)))
				}
				batch = batch[:0]
			}
		}
		for {
			select {
			case e, ok := <-queue:
				if !ok {
					flush()
					return
				}
				batch = append(batch, e)
				if len(batch) == cap(batch) {
					flush()
				}
			case <-timer.C:
				flush()
			}
		}
	}()
	return func() {
		_ = sock.Close()
		<-readerDone
		<-writerDone
	}
}

func (r *Runtime) stop() error {
	s := r.current
	if s == nil {
		return nil
	}
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("stop Suricata: %w", err)
	}
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill Suricata: %w", err)
		}
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
			return errors.New("Suricata did not stop")
		}
	}
	s.stopIO()
	r.lastLogs = s.log.snapshot()
	_ = os.RemoveAll(s.dir)
	r.current = nil
	return nil
}

func (r *Runtime) Activate(c Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.stop()
	if err == nil {
		err = r.start(c)
	}
	r.error = ""
	if err != nil {
		r.error = err.Error()
	}
	return err
}

func (r *Runtime) start(c Config) error {
	if err := Validate(c); err != nil {
		return err
	}
	if !c.Enabled {
		return nil
	}
	links, err := interfaces(c)
	if err != nil {
		return err
	}
	if c.Inline() {
		q, err := readQueue()
		if err != nil {
			return err
		}
		if q != nil {
			return fmt.Errorf("Очередь NFQUEUE %d уже занята", QueueNumber)
		}
	}
	dir, err := r.stage(c)
	if err != nil {
		return err
	}
	sock, err := r.listen(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	s := &sensor{dir: dir, config: c, links: links, done: make(chan struct{}), log: newSensorLog()}
	s.stopIO = r.collect(sock, RuleHash(c))
	s.cmd = r.command(context.Background(), dir, c, true)
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	if err = s.cmd.Start(); err != nil {
		s.stopIO()
		_ = os.RemoveAll(dir)
		return err
	}
	r.current = s
	go func() {
		_ = s.cmd.Wait()
		close(s.done)
	}()
	select {
	case <-s.log.ready:
		if c.Inline() && c.FailurePolicy == "open" {
			for _, line := range s.log.snapshot() {
				if strings.Contains(line, "can't set fail-open mode") || strings.Contains(line, "set but NFQ library has no support") {
					return errors.Join(errors.New("Ядро или Suricata не применили fail-open для переполнения"), r.stop())
				}
			}
		}
		if c.Inline() {
			var q *QueueStatus
			q, err = readQueue()
			if err == nil && q != nil {
				s.queuePeer = q.PortID
			}
		}
		if err = r.verify(c); err == nil {
			return nil
		}
	case <-s.done:
		err = errors.New("Suricata завершился при запуске")
	case <-time.After(10 * time.Second):
		err = errors.New("Suricata не подтвердил готовность за 10 секунд")
	}
	return errors.Join(err, r.stop())
}

func (r *Runtime) verify(c Config) error {
	if !c.Enabled && r.current == nil {
		return nil
	}
	s := r.current
	if s == nil || !reflect.DeepEqual(s.config, c) {
		return errors.New("Suricata не запущен с нужной конфигурацией")
	}
	select {
	case <-s.done:
		return errors.New("Процесс Suricata остановлен")
	default:
	}
	if c.Inline() {
		q, err := readQueue()
		if err != nil || q == nil || s.queuePeer == 0 || q.PortID != s.queuePeer {
			return errors.New("Suricata не владеет очередью NFQUEUE")
		}
	}
	links, err := interfaces(c)
	if err != nil || !reflect.DeepEqual(s.links, links) {
		return errors.New("Интерфейс Suricata недоступен или был пересоздан")
	}
	return nil
}

func (r *Runtime) Verify(c Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verify(c)
}

func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{Interfaces: []string{}, Dropped: r.dropped.Load(), Error: r.error}
	if r.current != nil {
		c := r.current.config
		s.Mode = "ids"
		if c.Inline() {
			s.Mode = "ips"
			if q, _ := readQueue(); q != nil && q.PortID == r.current.queuePeer {
				s.Queue = q
			}
		}
		s.Interfaces, s.RuleSHA256 = c.Interfaces, RuleHash(c)
		if c.FileIOC != nil {
			s.FileIOCSnapshot = c.FileIOC.Snapshot
		}
		if err := r.verify(c); err != nil {
			s.Error = err.Error()
		} else {
			s.Running = true
		}
	}
	return s
}

func (r *Runtime) Alerts(limit int, before int64) ([]Alert, error) {
	return readEvents(r.db, limit, before)
}

func (r *Runtime) AlertsAfter(id int64) ([]Alert, error) {
	return queryEvents(r.db, " WHERE id>? ORDER BY id LIMIT 100", id)
}

func (r *Runtime) Logs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil {
		return r.current.log.snapshot()
	}
	return append([]string{}, r.lastLogs...)
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.stop(); err != nil {
		return err
	}
	return errors.Join(r.db.Close(), r.lock.Close())
}
