// Package audit orchestrates a scan: gather inventory once, run every agent,
// then fold their output into the single Scan object the dashboard renders.
package audit

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/alminisl/security-bot/internal/collect"
	"github.com/alminisl/security-bot/internal/model"
	"github.com/alminisl/security-bot/internal/store"
)

type Options struct {
	Deep     bool          // run registry and CVE checks
	Timeout  time.Duration // per-command timeout
	Narrator Narrator      // optional; writes the auditor's report
	Log      *log.Logger
}

// Narrator turns a finished scan into a short written report. Implemented by
// the ollama client; nil is fine.
type Narrator interface {
	Report(ctx context.Context, sc *model.Scan) (string, error)
}

// Run performs a full audit and persists it.
func Run(ctx context.Context, st *store.Store, opt Options) (*model.Scan, error) {
	if opt.Timeout == 0 {
		opt.Timeout = 30 * time.Second
	}
	logf := func(format string, a ...any) {
		if opt.Log != nil {
			opt.Log.Printf(format, a...)
		}
	}

	started := time.Now()
	sc := &model.Scan{
		ID:        started.UTC().Format("20060102-150405"),
		StartedAt: started,
		Facts:     map[string]string{},
	}

	containers, err := collect.Inventory(ctx, opt.Timeout)
	if err != nil {
		return nil, fmt.Errorf("docker inventory: %w", err)
	}
	sc.Containers = containers
	logf("inventory: %d running containers", len(containers))

	env := &collect.Env{
		Containers: containers,
		Store:      st,
		Base:       st.Baseline(),
		Timeout:    opt.Timeout,
		DeepScan:   opt.Deep,
	}

	for _, ag := range collect.All() {
		run := model.AgentRun{Name: ag.Name(), Title: ag.Title(), Role: ag.Role(), Status: "ok"}
		t0 := time.Now()
		res, err := ag.Run(ctx, env)
		run.DurMS = time.Since(t0).Milliseconds()
		run.Checks = res.Checks
		run.Message = res.Message
		switch {
		case err != nil:
			run.Status = "failed"
			run.Message = err.Error()
			logf("agent %s failed: %v", ag.Name(), err)
		case res.Unavailable:
			run.Status = "unavailable"
		}
		run.Findings = len(res.Findings)
		sc.Findings = append(sc.Findings, res.Findings...)
		sc.Suggestions = append(sc.Suggestions, res.Suggestions...)
		sc.Agents = append(sc.Agents, run)
		logf("agent %s: %s (%d findings, %dms)", ag.Name(), run.Status, len(res.Findings), run.DurMS)
	}

	// Collapse any duplicate IDs an agent produced. The ID keys both the
	// ledger and the DOM, so duplicates would corrupt first-seen tracking and
	// render two elements with the same id.
	sc.Findings = dedupe(sc.Findings)

	// Mark what is new, and carry first-seen dates forward.
	prev := st.PrevFindingIDs()
	ledger := st.Ledger()
	today := started.UTC().Format(time.RFC3339)
	current := map[string]bool{}
	for i := range sc.Findings {
		f := &sc.Findings[i]
		current[f.ID] = true
		if fs, ok := ledger[f.ID]; ok {
			f.FirstSeen = fs
		} else {
			ledger[f.ID] = today
			f.FirstSeen = today
		}
		if len(prev) > 0 && !prev[f.ID] {
			f.New = true
			sc.NewCount++
		}
	}
	for id := range prev {
		if !current[id] {
			sc.Resolved++
			delete(ledger, id)
		}
	}

	model.SortFindings(sc.Findings)
	sc.Counts = model.CountBySeverity(sc.Findings)
	sc.Score = model.ScoreOf(sc.Findings)
	sc.Alerts = model.Alerts(sc.Findings)
	sc.Projects, sc.Machine, sc.Network = buildScopes(sc.Findings, containers)
	sc.Suggestions = append(sc.Suggestions, derivedSuggestions(sc)...)
	model.SortSuggestions(sc.Suggestions)
	sc.DurMS = time.Since(started).Milliseconds()

	sc.Facts["containers"] = fmt.Sprintf("%d", len(containers))
	sc.Facts["projects"] = fmt.Sprintf("%d", len(sc.Projects))
	sc.Facts["mode"] = map[bool]string{true: "full", false: "quick"}[opt.Deep]

	// The written report comes last: it summarises everything above. A 4B
	// model generating 300 tokens on CPU takes 90s or more, so the budget is
	// generous — the scan itself is already complete and saved either way.
	if opt.Narrator != nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		rep, err := opt.Narrator.Report(rctx, sc)
		cancel()
		if err != nil {
			logf("narrator unavailable: %v", err)
			sc.Report = fallbackReport(sc)
		} else {
			sc.Report = rep
		}
	} else {
		sc.Report = fallbackReport(sc)
	}

	if err := st.SaveBaseline(env.Base); err != nil {
		logf("save baseline: %v", err)
	}
	if err := st.SaveLedger(ledger); err != nil {
		logf("save ledger: %v", err)
	}
	if err := st.SaveScan(sc); err != nil {
		return sc, fmt.Errorf("save scan: %w", err)
	}
	if err := st.Prune(60); err != nil {
		logf("prune: %v", err)
	}
	return sc, nil
}

// dedupe keeps the first finding for each ID.
func dedupe(fs []model.Finding) []model.Finding {
	seen := make(map[string]bool, len(fs))
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

// buildScopes splits findings into per-project, machine and network ratings.
func buildScopes(fs []model.Finding, cs []model.Container) ([]model.ScopeScore, model.ScopeScore, model.ScopeScore) {
	byKey := map[string][]model.Finding{}
	for _, f := range fs {
		byKey[string(f.Scope)+"/"+f.ScopeKey] = append(byKey[string(f.Scope)+"/"+f.ScopeKey], f)
	}
	mk := func(scope model.Scope, key string) model.ScopeScore {
		group := byKey[string(scope)+"/"+key]
		ss := model.ScopeScore{
			Key:    key,
			Scope:  scope,
			Score:  model.ScoreOf(group),
			Counts: model.CountBySeverity(group),
		}
		for _, f := range group {
			ss.Findings = append(ss.Findings, f.ID)
		}
		return ss
	}

	// Every compose project that has containers gets a card, even a clean one.
	projects := collect.Projects(cs)
	var out []model.ScopeScore
	for name, members := range projects {
		ss := mk(model.ScopeProject, name)
		for _, c := range members {
			ss.Items = append(ss.Items, c.Name)
			if ss.Path == "" {
				ss.Path = c.WorkingDir
			}
		}
		sort.Strings(ss.Items)
		out = append(out, ss)
	}
	// Worst first, then alphabetical, so attention lands where it is needed.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score < out[j].Score
		}
		return out[i].Key < out[j].Key
	})

	machine := mk(model.ScopeMachine, "machine")
	network := mk(model.ScopeNetwork, "network")
	return out, machine, network
}

// derivedSuggestions adds advice that comes from the shape of the whole scan
// rather than from any single agent.
func derivedSuggestions(sc *model.Scan) []model.Suggestion {
	var out []model.Suggestion
	if n := sc.Counts["critical"]; n > 0 {
		out = append(out, model.NewSuggestion(model.Suggestion{
			Title:    fmt.Sprintf("Clear %d critical finding(s) first", n),
			Why:      "Critical findings here mean host-level compromise is one bug away — they outweigh everything else on this list.",
			Action:   "Work the alert band at the top of the dashboard before anything else.",
			Priority: 1,
			Effort:   "medium",
		}))
	}
	// Quick wins: cheap fixes that the UI can apply directly.
	quick := 0
	for _, f := range sc.Findings {
		if f.FixApply {
			quick++
		}
	}
	if quick > 0 {
		out = append(out, model.NewSuggestion(model.Suggestion{
			Title:    fmt.Sprintf("%d finding(s) can be fixed from the dashboard", quick),
			Why:      "These have a safe, reversible one-line fix already prepared.",
			Action:   "Review and apply them from the findings list.",
			Priority: 2,
			Effort:   "quick",
		}))
	}
	return out
}

// fallbackReport is used when no local model is available. It stays factual
// rather than pretending to be the auditor's prose.
func fallbackReport(sc *model.Scan) string {
	s := fmt.Sprintf("Audited %d containers across %d projects in %.1fs. Overall rating %d/100.",
		len(sc.Containers), len(sc.Projects), float64(sc.DurMS)/1000, sc.Score)
	if sc.Counts["critical"] > 0 || sc.Counts["high"] > 0 {
		s += fmt.Sprintf(" %d critical and %d high findings need attention.",
			sc.Counts["critical"], sc.Counts["high"])
	} else {
		s += " No critical or high findings."
	}
	if len(sc.Projects) > 0 {
		s += fmt.Sprintf(" Weakest project: %s (%d/100).", sc.Projects[0].Key, sc.Projects[0].Score)
	}
	if sc.NewCount > 0 {
		s += fmt.Sprintf(" %d finding(s) are new since the last scan.", sc.NewCount)
	}
	if sc.Resolved > 0 {
		s += fmt.Sprintf(" %d resolved.", sc.Resolved)
	}
	return s
}
