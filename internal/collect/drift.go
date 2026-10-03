package collect

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/alminisl/security-bot/internal/model"
)

// DriftWatcher is the closest thing here to compromise detection. It cannot
// prove the system is clean; what it can do is notice change — files appearing
// inside containers that the image never shipped, image digests swapping under
// a running container, containers appearing that were not there yesterday.
type DriftWatcher struct{}

func (DriftWatcher) Name() string  { return "drift-watcher" }
func (DriftWatcher) Title() string { return "Drift Watcher" }
func (DriftWatcher) Role() string {
	return "Baselines the system and reports change: modified container filesystems, swapped images, new containers."
}

// suspiciousDirs are paths where a new or changed file is more interesting than
// usual: binaries, startup, cron, ssh.
var suspiciousDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/etc/cron",
	"/root/.ssh", "/etc/ssh", "/etc/passwd", "/etc/shadow", "/usr/local/bin"}

func (a DriftWatcher) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	base := env.Base
	nowChanges := map[string]int{}
	nowDigests := map[string]string{}
	var nowNames []string

	known := map[string]bool{}
	for _, n := range base.Containers {
		known[n] = true
	}
	firstRun := len(base.Containers) == 0

	// `docker diff` costs a round-trip each and this box runs 35 containers,
	// so fan them out rather than paying ~1s apiece in series.
	diffs := make([]string, len(env.Containers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, c := range env.Containers {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := sh(ctx, env.Timeout, "docker", "diff", name)
			if err == nil {
				diffs[i] = out
			}
		}(i, c.Name)
	}
	wg.Wait()

	for i, c := range env.Containers {
		nowNames = append(nowNames, c.Name)
		nowDigests[c.Name] = c.ImageDigest
		r.Checks += 2

		changed := lines(diffs[i])
		nowChanges[c.Name] = len(changed)

		var hot []string
		for _, l := range changed {
			// Format is "A /path", "C /path" or "D /path".
			if len(l) < 3 {
				continue
			}
			kind, path := l[0], strings.TrimSpace(l[1:])
			if kind == 'D' {
				continue
			}
			for _, d := range suspiciousDirs {
				if strings.HasPrefix(path, d) {
					hot = append(hot, string(kind)+" "+path)
					break
				}
			}
		}
		if len(hot) > 0 {
			r.Findings = append(r.Findings, model.NewFinding(model.Finding{
				Agent:    a.Name(),
				Rule:     "container-fs-drift",
				Title:    fmt.Sprintf("%d file(s) changed in sensitive paths", len(hot)),
				Severity: model.SevMedium,
				Scope:    model.ScopeProject,
				ScopeKey: c.Project,
				Target:   c.Name,
				Detail: "Files differ from the image in locations that matter: " +
					truncate(strings.Join(hot, "; "), 300) +
					". This can be legitimate (an entrypoint writing config) but it is also what a dropped " +
					"binary or modified cron looks like. Verify once, and it becomes the accepted baseline.",
				Fix:    "Inspect the changes and confirm they are expected.",
				FixCmd: "docker diff " + c.Name,
			}))
		}

		// Image digest changed under a running container.
		if prev, ok := base.ImageDigest[c.Name]; ok && prev != "" && c.ImageDigest != "" && prev != c.ImageDigest {
			r.Findings = append(r.Findings, model.NewFinding(model.Finding{
				Agent:    a.Name(),
				Rule:     "image-digest-changed",
				Title:    "Image digest changed since last scan",
				Severity: model.SevLow,
				Scope:    model.ScopeProject,
				ScopeKey: c.Project,
				Target:   c.Name,
				Detail: "Was " + short(prev) + ", now " + short(c.ImageDigest) +
					". Expected if watchtower or you updated it; worth a look if neither did.",
				Fix: "Confirm this matches an update you or watchtower performed.",
			}))
		}

		// A large jump in changed files is worth flagging on its own.
		if prev, ok := base.FileChanges[c.Name]; ok && len(changed) > prev+200 {
			r.Findings = append(r.Findings, model.NewFinding(model.Finding{
				Agent:    a.Name(),
				Rule:     "fs-change-spike",
				Title:    fmt.Sprintf("Container filesystem grew by %d files", len(changed)-prev),
				Severity: model.SevLow,
				Scope:    model.ScopeProject,
				ScopeKey: c.Project,
				Target:   c.Name,
				Detail: fmt.Sprintf("Changed files went from %d to %d since the last scan. Usually cache or logs "+
					"written inside the container rather than to a volume.", prev, len(changed)),
				Fix: "If this is cache or log data, mount a volume for it so the container layer stays clean.",
			}))
		}
	}

	// Containers that appeared since the baseline.
	if !firstRun {
		for _, n := range nowNames {
			if !known[n] {
				r.Findings = append(r.Findings, model.NewFinding(model.Finding{
					Agent:    a.Name(),
					Rule:     "new-container",
					Title:    "New container since last scan: " + n,
					Severity: model.SevInfo,
					Scope:    model.ScopeProject,
					ScopeKey: projectOf(env.Containers, n),
					Target:   n,
					Detail:   "This container was not running at the previous scan. Expected if you deployed it.",
					Fix:      "Confirm you started this container.",
				}))
			}
		}
	}

	base.FileChanges = nowChanges
	base.ImageDigest = nowDigests
	base.Containers = nowNames

	if firstRun {
		r.Message = fmt.Sprintf("baseline recorded for %d containers", len(nowNames))
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title:    "Review the first drift baseline",
			Why:      "This run recorded the current state as normal. Anything already wrong is now baked into the baseline as expected.",
			Action:   "Skim the container filesystem findings once; from the next scan onward only changes are reported.",
			Scope:    model.ScopeProject,
			Priority: 3,
			Effort:   "quick",
		}))
	} else {
		r.Message = fmt.Sprintf("compared %d containers against baseline", len(nowNames))
	}
	return r, nil
}

func projectOf(cs []model.Container, name string) string {
	for _, c := range cs {
		if c.Name == name {
			return c.Project
		}
	}
	return "standalone"
}
