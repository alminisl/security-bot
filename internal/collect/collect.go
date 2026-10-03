// Package collect holds the agents. Each agent is one specialist that inspects
// a slice of the system and reports findings plus suggestions.
package collect

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
	"github.com/alminisl/security-bot/internal/store"
)

// Env is the shared context handed to every agent: the container inventory is
// gathered once, not re-shelled per agent.
type Env struct {
	Containers []model.Container
	Store      *store.Store
	Base       *store.Baseline
	Timeout    time.Duration
	DeepScan   bool      // allow slow work (registry calls, CVE scans)
	Since      time.Time // start of the previous scan; zero on the first run
}

// Result is what an agent reports back. Beyond findings, an agent may return
// inventory the dashboard lists whether or not anything is wrong with it.
type Result struct {
	Findings    []model.Finding
	Suggestions []model.Suggestion
	Inventory   []model.PackageSet
	Devices     []model.Device
	Flows       []model.Flow
	NetUsage    []model.ContainerTraffic
	Checks      int
	Message     string
	Unavailable bool // a required external tool is missing; not an error
}

// Agent is one security specialist on the roster.
type Agent interface {
	Name() string
	Title() string
	Role() string
	Run(ctx context.Context, env *Env) (Result, error)
}

// All returns the roster in dashboard order.
func All() []Agent {
	return []Agent{
		ContainerAuditor{},
		SecretScanner{},
		UpdateWatcher{},
		DriftWatcher{},
		VulnScanner{},
		MachineAuditor{},
		NetworkAuditor{},
		PackageAuditor{},
		DeviceAuditor{},
		TrafficWatcher{},
	}
}

// ErrToolMissing signals an optional dependency is absent.
var ErrToolMissing = errors.New("tool not installed")

// sh runs a command with a timeout and returns trimmed stdout. Agents shell out
// to docker/apt/ss rather than linking SDKs: fewer dependencies, and it works
// with exactly the permissions the user already has.
func sh(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return s, errors.New(msg)
	}
	return s, nil
}

func have(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
