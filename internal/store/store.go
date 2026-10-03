// Package store persists scans, the finding ledger and the drift baseline as
// plain JSON files. A POC does one scan a day, so files are plenty; swapping in
// SQLite later only touches this package.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

type Store struct {
	Dir string
}

// Open resolves the state directory, honouring XDG_STATE_HOME, and creates it.
func Open(dir string) (*Store, error) {
	if dir == "" {
		if x := os.Getenv("XDG_STATE_HOME"); x != "" {
			dir = filepath.Join(x, "sentinel")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			dir = filepath.Join(home, ".local", "state", "sentinel")
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "scans"), 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.Dir}, parts...)...)
}

// writeJSON writes atomically so a crash mid-write cannot leave the dashboard
// reading a truncated scan.
func (s *Store) writeJSON(rel string, v any) error {
	p := s.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (s *Store) readJSON(rel string, v any) error {
	b, err := os.ReadFile(s.path(rel))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Ledger remembers when each finding was first seen, which is how the UI can
// say "new today" and "open for 9 days".
type Ledger map[string]string

func (s *Store) Ledger() Ledger {
	l := Ledger{}
	_ = s.readJSON("ledger.json", &l)
	return l
}

func (s *Store) SaveLedger(l Ledger) error { return s.writeJSON("ledger.json", l) }

// Baseline holds the previous observed state the drift agent compares against:
// per-container changed-file counts, image digests and host listening ports.
type Baseline struct {
	UpdatedAt   time.Time         `json:"updatedAt"`
	FileChanges map[string]int    `json:"fileChanges"`
	ImageDigest map[string]string `json:"imageDigest"`
	ListenPorts []string          `json:"listenPorts"`
	Containers  []string          `json:"containers"`
	Devices     []string          `json:"devices"`
	// Flows maps "proto/remote:port" to how many sample windows it appeared
	// in, so the traffic watcher can tell a new destination from a regular one.
	Flows    map[string]int   `json:"flows"`
	NetTotal map[string]int64 `json:"netTotal"`
}

func (s *Store) Baseline() *Baseline {
	b := &Baseline{
		FileChanges: map[string]int{},
		ImageDigest: map[string]string{},
		Flows:       map[string]int{},
		NetTotal:    map[string]int64{},
	}
	_ = s.readJSON("baseline.json", b)
	if b.FileChanges == nil {
		b.FileChanges = map[string]int{}
	}
	if b.ImageDigest == nil {
		b.ImageDigest = map[string]string{}
	}
	if b.Flows == nil {
		b.Flows = map[string]int{}
	}
	if b.NetTotal == nil {
		b.NetTotal = map[string]int64{}
	}
	return b
}

func (s *Store) SaveBaseline(b *Baseline) error {
	b.UpdatedAt = time.Now()
	return s.writeJSON("baseline.json", b)
}

// SaveScan stores the scan, points "latest" at it and appends to the trend.
func (s *Store) SaveScan(sc *model.Scan) error {
	if err := s.writeJSON(filepath.Join("scans", sc.ID+".json"), sc); err != nil {
		return err
	}
	if err := s.writeJSON("latest.json", sc); err != nil {
		return err
	}
	h := s.History()
	h = append(h, model.HistoryPoint{At: sc.StartedAt, Score: sc.Score, Counts: sc.Counts})
	if len(h) > 180 {
		h = h[len(h)-180:]
	}
	return s.writeJSON("history.json", h)
}

func (s *Store) Latest() (*model.Scan, error) {
	sc := &model.Scan{}
	if err := s.readJSON("latest.json", sc); err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *Store) History() []model.HistoryPoint {
	var h []model.HistoryPoint
	_ = s.readJSON("history.json", &h)
	return h
}

// PrevFindingIDs returns the finding IDs from the previous scan, used to work
// out what is new and what was resolved.
func (s *Store) PrevFindingIDs() map[string]bool {
	out := map[string]bool{}
	prev, err := s.Latest()
	if err != nil {
		return out
	}
	for _, f := range prev.Findings {
		out[f.ID] = true
	}
	return out
}

// Prune keeps the newest n scan files.
func (s *Store) Prune(n int) error {
	ents, err := os.ReadDir(s.path("scans"))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= n {
		return nil
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-n] {
		if err := os.Remove(s.path("scans", name)); err != nil {
			return fmt.Errorf("prune %s: %w", name, err)
		}
	}
	return nil
}
