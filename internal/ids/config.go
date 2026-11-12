package ids

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const QueueNumber = 43013

type Config struct {
	FileIOC       *FileIOC `json:"file_ioc,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	FailurePolicy string   `json:"failure_policy,omitempty"`
	Enabled       bool     `json:"enabled"`
	Interfaces    []string `json:"interfaces"`
	HomeNet       []string `json:"home_net"`
	Rules         string   `json:"rules"`
}

func (c Config) Inline() bool { return c.Enabled && c.Mode == "ips" }

func Empty() Config { return Config{Interfaces: []string{}, HomeNet: []string{}} }

type Plan struct {
	CanApply bool     `json:"can_apply"`
	Checked  bool     `json:"checked"`
	Actions  []string `json:"actions"`
	Warnings []string `json:"warnings"`
}

type Status struct {
	FileIOCSnapshot string       `json:"file_ioc_snapshot,omitempty"`
	Mode            string       `json:"mode,omitempty"`
	Queue           *QueueStatus `json:"queue,omitempty"`
	Running         bool         `json:"running"`
	Interfaces      []string     `json:"interfaces"`
	RuleSHA256      string       `json:"rule_sha256,omitempty"`
	Error           string       `json:"error,omitempty"`
	Dropped         uint64       `json:"dropped_events"`
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var forbiddenOption = regexp.MustCompile(`(?i)\b(dataset|datarep|lua|luajit|filestore|filemd5|filesha1|filesha256|tag|bypass)\s*[:;]`)

func Validate(c Config) error {
	if err := c.FileIOC.Validate(); err != nil {
		return err
	}
	if c.Mode != "" && c.Mode != "ids" && c.Mode != "ips" {
		return errors.New("Выберите режим IDS или IPS")
	}
	if c.Mode == "ips" {
		if c.FailurePolicy != "open" && c.FailurePolicy != "closed" {
			return errors.New("Выберите поведение IPS при недоступности и переполнении очереди")
		}
	} else if c.FailurePolicy != "" {
		return errors.New("Политика отказа применяется только в режиме IPS")
	}
	if len(c.Interfaces) > 4 || len(c.HomeNet) > 64 || len(c.Rules) > 256<<10 || !utf8.ValidString(c.Rules) {
		return errors.New("IDS: до 4 интерфейсов, 64 подсетей HOME_NET и 256 КиБ правил UTF-8")
	}
	seen := make(map[string]bool)
	for _, name := range c.Interfaces {
		if !interfaceName.MatchString(name) || name == "lo" || seen[name] {
			return errors.New("IDS: интерфейсы должны быть уникальными, loopback исключён")
		}
		seen[name] = true
	}
	for _, subnet := range c.HomeNet {
		p, err := netip.ParsePrefix(subnet)
		if err != nil || p != p.Masked() || p.Addr().Is4In6() {
			return errors.New("IDS: HOME_NET принимает IPv4/IPv6 CIDR без битов хоста")
		}
	}
	count := 0
	for i, raw := range strings.Split(c.Rules, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if count > 2048 || len(line) > 8192 {
			return errors.New("IDS: до 2048 правил, по одному правилу на строку до 8192 байт")
		}
		fields := strings.Fields(line)
		if (fields[0] != "alert" && (c.Mode != "ips" || fields[0] != "drop")) || strings.HasSuffix(line, "\\") ||
			forbiddenOption.MatchString(line) || (c.FileIOC != nil && reservedFileSID(line)) ||
			strings.ContainsFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) {
			return fmt.Errorf("IDS: строка %d допустимы alert для IDS, alert и drop для IPS, без файлов, скриптов и обхода проверки", i+1)
		}
	}
	if c.Enabled && (len(c.Interfaces) == 0 || len(c.HomeNet) == 0 || (count == 0 && c.FileIOC == nil)) {
		return errors.New("IDS: выберите интерфейс, задайте HOME_NET и добавьте хотя бы одну сигнатуру")
	}
	return nil
}

func RuleHash(c Config) string {
	text := c.Rules
	if c.FileIOC != nil {
		text += "\x00" + c.FileIOC.Snapshot
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func Preview(c Config) Plan {
	p := Plan{
		Actions:  []string{"Остановить управляемый Suricata"},
		Warnings: []string{"Пассивный AF_PACKET создаёт алерты. Правила фильтрации и доступ через LAN действуют независимо."},
	}
	if c.Enabled {
		p.Actions = []string{
			"Запустить Suricata IDS на " + strings.Join(c.Interfaces, ", "),
			"HOME_NET " + strings.Join(c.HomeNet, ", "),
			"SHA-256 локальных правил " + RuleHash(c),
		}
	}
	if c.Inline() {
		p.Actions[0] = "Проверять разрешённый firewall транзит в обоих направлениях на " + strings.Join(c.Interfaces, ", ")
		p.Warnings = []string{"NFQUEUE применяется только к транзиту. Доступ к панели через LAN вне очереди."}
		if c.FailurePolicy == "open" {
			p.Warnings = append(p.Warnings, "Без слушателя или при заполнении очереди новый трафик может пройти без проверки. При закрытии сокета ожидающие пакеты могут быть потеряны.")
		} else {
			p.Warnings = append(p.Warnings, "Без слушателя или при заполнении очереди выбранный транзит блокируется.")
		}
	}
	if c.Enabled && c.FileIOC != nil {
		p.Actions = append(p.Actions, fmt.Sprintf("Файловые IOC HTTP: %d хэшей, снимок %s", c.FileIOC.Count(), c.FileIOC.Snapshot))
	}
	return p
}

type QueueStatus struct {
	PortID        uint64 `json:"-"`
	Waiting       uint64 `json:"waiting"`
	KernelDropped uint64 `json:"kernel_dropped"`
	UserDropped   uint64 `json:"user_dropped"`
}

type Backend interface {
	Prepare(Config) (Plan, error)
	Activate(Config) error
	Verify(Config) error
	Status() Status
	Alerts(int, int64) ([]Alert, error)
	Logs() []string
	Close() error
}
