package ids

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rkislov/gfw/internal/feed"
)

const MaxFileIOCBytes = 1 << 20

type FileIOC struct {
	Snapshot string            `json:"snapshot_sha256"`
	Lists    map[string]string `json:"lists"`
}

var sidOption = regexp.MustCompile(`(?i)\bsid\s*:\s*([0-9]+)`)

func (f *FileIOC) Validate() error {
	if f == nil {
		return nil
	}
	if !feed.ValidHash("sha256", f.Snapshot) || len(f.Lists) == 0 || len(f.Lists) > 3 {
		return errors.New("Некорректный снимок файловых IOC")
	}
	total := 0
	for algo, list := range f.Lists {
		total += len(list)
		if total > MaxFileIOCBytes || list == "" || !strings.HasSuffix(list, "\n") {
			return errors.New("Некорректный размер списка файловых IOC")
		}
		for value := range strings.SplitSeq(strings.TrimSuffix(list, "\n"), "\n") {
			if !feed.ValidHash(algo, value) {
				return errors.New("Некорректный хэш в списке файловых IOC")
			}
		}
	}
	return nil
}

func (f *FileIOC) Count() int {
	count := 0
	if f != nil {
		for _, list := range f.Lists {
			count += strings.Count(list, "\n")
		}
	}
	return count
}

func reservedFileSID(line string) bool {
	for _, match := range sidOption.FindAllStringSubmatch(line, -1) {
		sid, _ := strconv.ParseUint(match[1], 10, 32)
		if sid >= 3980001 && sid <= 3980003 {
			return true
		}
	}
	return false
}

func (f *FileIOC) AddRules(files map[string]string) {
	if f == nil {
		return
	}
	for i, algorithm := range []string{"md5", "sha1", "sha256"} {
		if list := f.Lists[algorithm]; list != "" {
			name := "ioc-" + algorithm + ".txt"
			files[name] = list
			files["local.rules"] += fmt.Sprintf("alert http any any -> any any (msg:\"Security Feed: файловый IOC %s, снимок %s\"; file%s:%s; sid:%d; rev:1;)\n", algorithm, f.Snapshot, algorithm, name, 3980001+i)
		}
	}
}
