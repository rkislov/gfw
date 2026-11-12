package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/policy"
)

// Snapshot contains only the GFW-owned table; unrelated tables are never saved
// or changed by this backend.
type Snapshot struct {
	Exists bool   `json:"exists"`
	Rules  string `json:"rules"`
}
type Backend interface {
	Snapshot() (Snapshot, error)
	Check(Snapshot) error
	Replace(Snapshot) error
}

type NFT struct {
	Path string
	ips  bool
	flow bool
}

func (n NFT) ForIPS() NFT {
	n.ips = true
	return n
}

func (n NFT) ForFlow() NFT { n.flow = true; return n }

func (n NFT) identity() (string, string) {
	if n.flow {
		return policy.FlowTableName, policy.FlowOwner
	}
	if n.ips {
		return "gfw_ips", "gfw-ips-managed-v1"
	}
	return "gfw", policy.Owner
}

// nft 1.1.7 prints a folded label assignment without grouping its OR
// constant. Re-parsing that output can exceed the binary-expression limit.
// Restore the grouping without changing the mask, value, or any other rule.
var printedLabelAssignment = regexp.MustCompile(`ct label set ct label & (\([^)]*\)) \| ([0-9]+(?: \| [0-9]+)*)`)

func restorableRules(raw string) string {
	return printedLabelAssignment.ReplaceAllString(raw, `ct label set (ct label & $1) | ($2)`)
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("nft output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (n NFT) run(input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.Path, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out := &limitedBuffer{limit: 8 << 20}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}
func (n NFT) Snapshot() (Snapshot, error) {
	name, owner := n.identity()
	raw, err := n.run("", "-j", "list", "tables")
	if err != nil {
		return Snapshot{}, err
	}
	var list struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &list); err != nil {
		return Snapshot{}, err
	}
	exists := false
	for _, entry := range list.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == name {
			exists = true
		}
	}
	if !exists {
		return Snapshot{}, nil
	}
	raw, err = n.run("", "-j", "list", "table", "inet", name)
	if err != nil {
		return Snapshot{}, err
	}
	var doc struct {
		NFTables []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return Snapshot{}, err
	}
	owned := false
	for _, entry := range doc.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == name && entry.Table.Comment == owner {
			owned = true
		}
	}
	if !owned {
		return Snapshot{}, fmt.Errorf("inet %s exists without GFW ownership marker; refusing to modify it", name)
	}
	raw, err = n.run("", "-s", "-n", "list", "table", "inet", name)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Exists: true, Rules: restorableRules(string(raw))}, nil
}
func (n NFT) script(target Snapshot) (string, error) {
	current, err := n.Snapshot()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if current.Exists {
		name, _ := n.identity()
		fmt.Fprintf(&b, "delete table inet %s\n", name)
	}
	if target.Exists {
		b.WriteString(target.Rules)
	}
	return b.String(), nil
}
func (n NFT) Check(target Snapshot) error {
	script, err := n.script(target)
	if err != nil {
		return err
	}
	if script == "" {
		return nil
	}
	_, err = n.run(script, "-c", "-f", "-")
	return err
}
func (n NFT) Replace(target Snapshot) error {
	script, err := n.script(target)
	if err != nil {
		return err
	}
	if script == "" {
		return nil
	}
	_, err = n.run(script, "-f", "-")
	return err
}

// Prevent an accidental unbounded journal read in a privileged process.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, 32<<20+1))
	if err == nil && len(b) > 32<<20 {
		return nil, errors.New("journal exceeds 32 MiB")
	}
	return b, err
}
