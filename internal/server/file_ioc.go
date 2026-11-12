package server

import (
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/rkislov/gfw/internal/feed"
	"github.com/rkislov/gfw/internal/ids"
	"github.com/rkislov/gfw/internal/store"
)

func (s *Server) scanFileIOC(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" {
		fail(w, 415, "Передайте исходные байты файла")
		return
	}
	if r.ContentLength > feed.MaxScanFile {
		fail(w, 413, "Файл больше 16 МиБ")
		return
	}
	if !s.fileIOCMu.TryLock() {
		fail(w, 429, "Выполняется другая операция с файловыми IOC")
		return
	}
	defer s.fileIOCMu.Unlock()

	digests, size, err := feed.FileDigests(http.MaxBytesReader(w, r.Body, feed.MaxScanFile))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		fail(w, 413, "Файл больше 16 МиБ")
		return
	case err != nil:
		fail(w, 400, "Не удалось прочитать файл целиком")
		return
	}
	sha, at, raw, err := s.Store.ReadIOCFile(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 409, "Сначала загрузите IOC из Security Feed")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	out := struct {
		Snapshot  string               `json:"snapshot_sha256"`
		UpdatedAt string               `json:"snapshot_at"`
		Size      int64                `json:"size"`
		Digests   map[string]string    `json:"hashes"`
		Matches   []feed.FileIndicator `json:"matches"`
		More      bool                 `json:"more_matches"`
	}{sha, at, size, digests, []feed.FileIndicator{}, false}
	checked := false
	err = feed.VisitFileIndicators(r.Context(), raw, func(i feed.FileIndicator) error {
		checked = true
		if digests[i.Algorithm] == i.Hash && !slices.Contains(out.Matches, i) {
			if len(out.Matches) < 20 {
				out.Matches = append(out.Matches, i)
			} else {
				out.More = true
			}
		}
		return nil
	})
	if err != nil || !checked {
		fail(w, 422, "В снимке нет доступных для проверки файловых хэшей")
		return
	}
	respond(w, 200, out)
}

func (s *Server) stageFileIOC(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision int64  `json:"revision"`
		Snapshot string `json:"snapshot_sha256"`
	}
	if decode(w, r, &in) != nil || in.Revision < 1 || in.Snapshot != "" && !feed.ValidHash("sha256", in.Snapshot) {
		fail(w, 400, "Укажите ревизию и SHA-256 снимка или пустой SHA-256 для отключения")
		return
	}
	var pinned *ids.FileIOC
	if in.Snapshot != "" {
		if !s.fileIOCMu.TryLock() {
			fail(w, 429, "Выполняется другая операция с файловыми IOC")
			return
		}
		defer s.fileIOCMu.Unlock()
		sha, _, raw, err := s.Store.ReadIOCFile(r.Context())
		if errors.Is(err, sql.ErrNoRows) || err == nil && sha != in.Snapshot {
			fail(w, 409, "Снимок IOC изменился или отсутствует")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		pinned, err = pinFileIOC(r, sha, raw)
		if err != nil {
			fail(w, 422, err.Error())
			return
		}
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	draft, err := s.Store.ReadIDS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if draft.Revision != in.Revision {
		fail(w, 412, store.ErrConflict.Error())
		return
	}
	draft.Config.FileIOC = pinned
	if err = ids.Validate(draft.Config); err != nil {
		fail(w, 422, err.Error())
		return
	}
	if !fitsFeedDraft(draft.Config) {
		fail(w, 422, "Черновик со списком превышает размер запроса агента")
		return
	}
	snap, err := s.Store.SaveIDS(r.Context(), in.Revision, draft.Config)
	if errors.Is(err, store.ErrConflict) {
		fail(w, 412, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	respondIDS(w, snap)
}

func pinFileIOC(r *http.Request, sha string, raw []byte) (*ids.FileIOC, error) {
	seen := map[[2]string]bool{}
	lists := map[string][]string{}
	size := 0
	err := feed.VisitFileIndicators(r.Context(), raw, func(i feed.FileIndicator) error {
		key := [2]string{i.Algorithm, i.Hash}
		if seen[key] {
			return nil
		}
		size += len(i.Hash) + 1
		if size > ids.MaxFileIOCBytes {
			return errors.New("Список файловых IOC превышает 1 МиБ")
		}
		seen[key] = true
		lists[i.Algorithm] = append(lists[i.Algorithm], i.Hash)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(lists) == 0 {
		return nil, errors.New("В снимке нет файловых IOC")
	}
	pinned := &ids.FileIOC{Snapshot: sha, Lists: map[string]string{}}
	for algorithm, values := range lists {
		slices.Sort(values)
		pinned.Lists[algorithm] = strings.Join(values, "\n") + "\n"
	}
	return pinned, nil
}
