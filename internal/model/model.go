// Package model holds the data types shared by the agents, the store and the web UI.
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding. Stored as a string so the JSON state and the web
// UI read the same vocabulary.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Weight is how many points a finding of this severity removes from a scope's
// score. Info is observational and costs nothing.
func (s Severity) Weight() float64 {
	switch s {
	case SevCritical:
		return 25
	case SevHigh:
		return 8
	case SevMedium:
		return 2.5
	case SevLow:
		return 0.5
	}
	return 0
}

func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// Scope is where a finding lives: a compose project, the host machine, or the
// network. It drives the three sections of the dashboard.
type Scope string

const (
	ScopeProject  Scope = "project"
	ScopeMachine  Scope = "machine"
	ScopeNetwork  Scope = "network"
	ScopePackages Scope = "packages"
	ScopeTraffic  Scope = "traffic"
)

// Finding is one security observation. ID is derived from the agent, scope key
// and rule so the same issue keeps its identity across scans, which is what
// lets the dashboard show what is new and what was resolved.
type Finding struct {
	ID        string   `json:"id"`
	Agent     string   `json:"agent"`
	Rule      string   `json:"rule"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Scope     Scope    `json:"scope"`
	ScopeKey  string   `json:"scopeKey"` // project name, or "machine" / "network"
	Target    string   `json:"target"`   // container, image, path, port
	Detail    string   `json:"detail"`
	Fix       string   `json:"fix"`              // human instruction
	FixCmd    string   `json:"fixCmd,omitempty"` // copyable shell command
	FixApply  bool     `json:"fixApply"`         // safe to run from the UI
	Refs      []string `json:"refs,omitempty"`
	FirstSeen string   `json:"firstSeen,omitempty"`
	New       bool     `json:"new"`
}

// NewFinding fills in the stable ID. Call it rather than building Finding
// literals so IDs stay consistent.
func NewFinding(f Finding) Finding {
	h := sha1.Sum([]byte(f.Agent + "|" + f.ScopeKey + "|" + f.Rule + "|" + f.Target))
	f.ID = hex.EncodeToString(h[:])[:12]
	return f
}

// Mount, Port and Container mirror the parts of `docker inspect` the agents
// actually read.
type Port struct {
	Container string `json:"container"`
	HostIP    string `json:"hostIp"`
	HostPort  string `json:"hostPort"`
}

type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

type Container struct {
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	ImageDigest string   `json:"imageDigest,omitempty"`
	Project     string   `json:"project"`
	WorkingDir  string   `json:"workingDir,omitempty"`
	Status      string   `json:"status"`
	Health      string   `json:"health,omitempty"`
	StartedAt   string   `json:"startedAt,omitempty"`
	Privileged  bool     `json:"privileged"`
	NetworkMode string   `json:"networkMode"`
	User        string   `json:"user,omitempty"`
	CapAdd      []string `json:"capAdd,omitempty"`
	SecurityOpt []string `json:"securityOpt,omitempty"`
	ReadonlyFS  bool     `json:"readonlyFs"`
	MemLimit    int64    `json:"memLimit"`
	RestartPol  string   `json:"restartPolicy,omitempty"`
	Ports       []Port   `json:"ports,omitempty"`
	Mounts      []Mount  `json:"mounts,omitempty"`
	EnvKeys     []string `json:"-"`
	Env         []string `json:"-"`
	Watchtower  bool     `json:"watchtower"`
}

// PackageItem is one installed package.
type PackageItem struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Latest   string `json:"latest,omitempty"`
	Source   string `json:"source,omitempty"`
	Outdated bool   `json:"outdated,omitempty"`
	Security bool   `json:"security,omitempty"` // a security update is pending
}

// PackageSet is everything one package manager reports.
type PackageSet struct {
	Manager  string        `json:"manager"`
	Label    string        `json:"label"`
	Count    int           `json:"count"` // total known, which may exceed len(Items)
	Shown    string        `json:"shown"` // what Items actually contains
	Outdated int           `json:"outdated"`
	Items    []PackageItem `json:"items,omitempty"`
	Note     string        `json:"note,omitempty"`
}

// Device is one machine seen on the local network or the tailnet.
type Device struct {
	Name     string `json:"name"`
	Addr     string `json:"addr"`
	MAC      string `json:"mac,omitempty"`
	OS       string `json:"os,omitempty"`
	Source   string `json:"source"` // tailnet | arp | sweep
	Online   bool   `json:"online"`
	LastSeen string `json:"lastSeen,omitempty"`
	Note     string `json:"note,omitempty"`
	New      bool   `json:"new,omitempty"`
}

// Flow is traffic to one remote endpoint, rolled up by the sampler.
type Flow struct {
	Remote    string `json:"remote"`
	Port      string `json:"port"`
	Host      string `json:"host,omitempty"` // reverse DNS, when resolvable
	Proto     string `json:"proto"`
	Samples   int    `json:"samples"` // times seen across sampling runs
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
	New       bool   `json:"new,omitempty"`
	// Peer marks a connection that looks peer-to-peer rather than to a
	// service. Shown for context, never alerted on.
	Peer bool `json:"peer,omitempty"`
}

// ContainerTraffic is per-container byte counters and their drift.
type ContainerTraffic struct {
	Name     string  `json:"name"`
	RxBytes  int64   `json:"rxBytes"`
	TxBytes  int64   `json:"txBytes"`
	RxDelta  int64   `json:"rxDelta"`
	TxDelta  int64   `json:"txDelta"`
	Baseline int64   `json:"baseline"` // mean total delta per sample window
	Spike    float64 `json:"spike"`    // multiple of baseline, 0 when unknown
}

// AgentRun records one agent's execution: the roster on the dashboard is built
// from these.
type AgentRun struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Role     string `json:"role"`
	Status   string `json:"status"` // ok | failed | unavailable | running
	Message  string `json:"message,omitempty"`
	Findings int    `json:"findings"`
	DurMS    int64  `json:"durationMs"`
	Checks   int    `json:"checks"`
}

// Scope score: a rating out of 100 for one project, the machine or the network.
type ScopeScore struct {
	Key      string         `json:"key"`
	Scope    Scope          `json:"scope"`
	Path     string         `json:"path,omitempty"`
	Score    int            `json:"score"`
	Counts   map[string]int `json:"counts"`
	Findings []string       `json:"findings"` // finding IDs
	Items    []string       `json:"items"`    // container names
}

// Scan is one complete audit, and the single object the web UI renders.
type Scan struct {
	ID          string             `json:"id"`
	StartedAt   time.Time          `json:"startedAt"`
	DurMS       int64              `json:"durationMs"`
	Score       int                `json:"score"`
	Counts      map[string]int     `json:"counts"`
	Findings    []Finding          `json:"findings"`
	Containers  []Container        `json:"containers"`
	Projects    []ScopeScore       `json:"projects"`
	Machine     ScopeScore         `json:"machine"`
	Network     ScopeScore         `json:"network"`
	Packages    ScopeScore         `json:"packages"`
	Traffic     ScopeScore         `json:"traffic"`
	Inventory   []PackageSet       `json:"inventory,omitempty"`
	Devices     []Device           `json:"devices,omitempty"`
	Flows       []Flow             `json:"flows,omitempty"`
	NetUsage    []ContainerTraffic `json:"netUsage,omitempty"`
	Agents      []AgentRun         `json:"agents"`
	Report      string             `json:"report"`
	Suggestions []Suggestion       `json:"suggestions"`
	Alerts      []Finding          `json:"alerts"`
	Resolved    int                `json:"resolved"`
	NewCount    int                `json:"newCount"`
	Facts       map[string]string  `json:"facts,omitempty"`
}

func CountBySeverity(fs []Finding) map[string]int {
	c := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range fs {
		c[string(f.Severity)]++
	}
	return c
}

// ScoreOf rates a set of findings out of 100.
//
// Two properties matter more than the exact numbers. First, repeat occurrences
// of the same rule have diminishing cost: the sixth container mounting the
// Docker socket does not add as much risk as the first, and a scan that
// punished each one equally would rate every busy host at zero and stop being
// a signal. Second, the curve is asymptotic, so the score never bottoms out —
// fixing something always moves the number.
func ScoreOf(fs []Finding) int {
	byRule := map[string]struct {
		weight float64
		count  int
	}{}
	for _, f := range fs {
		e := byRule[f.Rule]
		e.weight = f.Severity.Weight()
		e.count++
		byRule[f.Rule] = e
	}
	penalty := 0.0
	for _, e := range byRule {
		// sqrt growth: 1 occurrence costs w, 4 cost 2w, 9 cost 3w.
		p := e.weight * math.Sqrt(float64(e.count))
		if p > maxRulePenalty {
			p = maxRulePenalty
		}
		penalty += p
	}
	if penalty <= 0 {
		return 100
	}
	return int(100.0/(1.0+penalty/penaltyScale) + 0.5)
}

const (
	// maxRulePenalty stops one noisy rule from dominating the whole rating.
	maxRulePenalty = 30.0
	// penaltyScale sets how fast the rating falls: a lone critical finding
	// lands around 70, a genuinely neglected host in the 20s.
	penaltyScale = 60.0
)

// SortFindings orders by severity then title, so the worst thing is first.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].ScopeKey != fs[j].ScopeKey {
			return fs[i].ScopeKey < fs[j].ScopeKey
		}
		return fs[i].Title < fs[j].Title
	})
}

// ShortImage trims a registry reference down to something readable in a card.
func ShortImage(ref string) string {
	s := strings.TrimPrefix(ref, "docker.io/library/")
	s = strings.TrimPrefix(s, "docker.io/")
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return s
}

// Suggestion is a recommended action. Findings describe what is wrong;
// suggestions describe what to do next, including advice no single finding
// covers (missing tooling, habits, coverage gaps).
type Suggestion struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Why      string `json:"why"`
	Action   string `json:"action,omitempty"`
	Cmd      string `json:"cmd,omitempty"`
	Scope    Scope  `json:"scope"`
	ScopeKey string `json:"scopeKey,omitempty"`
	Priority int    `json:"priority"` // 1 = do this first
	Effort   string `json:"effort"`   // quick | medium | project
}

func NewSuggestion(s2 Suggestion) Suggestion {
	h := sha1.Sum([]byte("sug|" + s2.ScopeKey + "|" + s2.Title))
	s2.ID = hex.EncodeToString(h[:])[:12]
	return s2
}

// SortSuggestions puts the highest priority, lowest effort work first.
func SortSuggestions(ss []Suggestion) {
	effort := map[string]int{"quick": 0, "medium": 1, "project": 2}
	sort.SliceStable(ss, func(i, j int) bool {
		if ss[i].Priority != ss[j].Priority {
			return ss[i].Priority < ss[j].Priority
		}
		return effort[ss[i].Effort] < effort[ss[j].Effort]
	})
}

// Alerts returns the findings that warrant reacting now. This is what the
// dashboard shows in its top band and what the notifier will send.
func Alerts(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity == SevCritical || f.Severity == SevHigh {
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out
}

// HistoryPoint is one entry in the score trend.
type HistoryPoint struct {
	At     time.Time      `json:"at"`
	Score  int            `json:"score"`
	Counts map[string]int `json:"counts"`
}
