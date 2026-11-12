package traffic

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const spoolLimit = 50000

type Collector struct {
	db                           *sql.DB
	queue                        chan Event
	stop                         context.CancelFunc
	sources, writer              sync.WaitGroup
	lost                         atomic.Uint64
	incompleteSnapshots          atomic.Uint64
	conntrack                    atomic.Bool
	nflog                        atomic.Bool
	nflogConntrack               atomic.Bool
	mu                           sync.Mutex
	lastError                    string
	device, boot, namespace, run string
	serial                       atomic.Uint64
}

func deviceID(dir string) (string, error) {
	path := filepath.Join(dir, "device-id")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return "", errors.New("invalid traffic device ID")
		}
		return string(b), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	value := hex.EncodeToString(id[:])
	return value, os.WriteFile(path, []byte(value), 0600)
}

func Open(dir string) (*Collector, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	device, err := deviceID(dir)
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	var run [16]byte
	if _, err = rand.Read(run[:]); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "spool.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500;
	PRAGMA max_page_count=32768; PRAGMA wal_autocheckpoint=256;
	CREATE TABLE IF NOT EXISTS spool(seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, body BLOB NOT NULL);
	CREATE TABLE IF NOT EXISTS totals(id INTEGER PRIMARY KEY CHECK(id=1), evicted INTEGER NOT NULL);
	INSERT OR IGNORE INTO totals VALUES(1,0);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Collector{db: db, queue: make(chan Event, 4096), stop: cancel, device: device, boot: strings.TrimSpace(string(boot)), namespace: ns, run: hex.EncodeToString(run[:])}
	c.writer.Add(1)
	go c.write()
	c.startSources(ctx)
	return c, nil
}

func (c *Collector) Close() error {
	c.stop()
	c.sources.Wait()
	close(c.queue)
	c.writer.Wait()
	return c.db.Close()
}

func (c *Collector) note(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = err.Error()
}

func (c *Collector) enqueue(e Event) {
	e.EventID = c.run + "-" + strconv.FormatUint(c.serial.Add(1), 10)
	e.Device, e.Boot, e.Namespace = c.device, c.boot, c.namespace
	select {
	case c.queue <- e:
	default:
		c.lost.Add(1)
	}
}

func (c *Collector) write() {
	defer c.writer.Done()
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	batch := make([]Event, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		op, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.append(op, batch); err != nil {
			c.lost.Add(uint64(len(batch)))
			c.note(err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, open := <-c.queue:
			if !open {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (c *Collector) append(ctx context.Context, batch []Event) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO spool(at,body) VALUES(?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	var last int64
	for _, e := range batch {
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		result, err := stmt.ExecContext(ctx, e.At, body)
		if err != nil {
			return err
		}
		last, err = result.LastInsertId()
		if err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM spool WHERE seq<=?", last-spoolLimit)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE totals SET evicted=evicted+? WHERE id=1", n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c *Collector) Peek(ctx context.Context) (Batch, error) {
	out := Batch{Events: []Event{}}
	rows, err := c.db.QueryContext(ctx, "SELECT seq,body FROM spool ORDER BY seq LIMIT ?", BatchSize)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var body []byte
		var e Event
		if err = rows.Scan(&out.Cursor, &body); err != nil {
			return out, err
		}
		if err = json.Unmarshal(body, &e); err != nil {
			return out, err
		}
		out.Events = append(out.Events, e)
	}
	return out, rows.Err()
}

func (c *Collector) Ack(ctx context.Context, seq int64) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM spool WHERE seq<=?", seq)
	return err
}

func (c *Collector) Status(ctx context.Context) (Status, error) {
	c.mu.Lock()
	message := c.lastError
	c.mu.Unlock()
	acct, _ := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	s := Status{Conntrack: c.conntrack.Load(), NFLOG: c.nflog.Load(), NFLOGConntrack: c.nflogConntrack.Load(), Lost: c.lost.Load(), IncompleteSnapshots: c.incompleteSnapshots.Load(), Error: message, Accounting: strings.TrimSpace(string(acct)) == "1"}
	err := c.db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM spool),COALESCE((SELECT at FROM spool ORDER BY seq LIMIT 1),0),evicted FROM totals WHERE id=1").Scan(&s.Queued, &s.Oldest, &s.Evicted)
	return s, err
}
