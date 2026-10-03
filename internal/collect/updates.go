package collect

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// UpdateWatcher compares the digest of each running image against the registry
// without pulling anything, so it can say "you are N builds behind" cheaply.
type UpdateWatcher struct{}

func (UpdateWatcher) Name() string  { return "update-watcher" }
func (UpdateWatcher) Title() string { return "Update Watcher" }
func (UpdateWatcher) Role() string {
	return "Compares running image digests against the registry to find containers behind their published version."
}

func (a UpdateWatcher) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	if !env.DeepScan {
		r.Message = "skipped (registry checks run in full scans)"
		return r, nil
	}

	// Which containers watchtower already keeps current? If WATCHTOWER_LABEL_ENABLE
	// is not set, watchtower updates everything it can see, so a pending update
	// is self-healing and only worth a note.
	wtAll, wtPresent := watchtowerScope(ctx, env.Timeout)

	// Group containers by image so each image is only queried once.
	byImage := map[string][]model.Container{}
	for _, c := range env.Containers {
		byImage[c.Image] = append(byImage[c.Image], c)
	}

	type res struct {
		image  string
		remote string
		err    error
	}
	var (
		mu      sync.Mutex
		results []res
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 4) // bound registry concurrency
	)
	for image, cs := range byImage {
		if cs[0].ImageDigest == "" {
			continue // locally built image, nothing to compare against
		}
		if !strings.Contains(image, ":") {
			continue
		}
		wg.Add(1)
		go func(image string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := sh(ctx, 45*time.Second, "docker", "buildx", "imagetools",
				"inspect", image, "--format", "{{.Manifest.Digest}}")
			mu.Lock()
			results = append(results, res{image: image, remote: strings.TrimSpace(out), err: err})
			mu.Unlock()
		}(image)
	}
	wg.Wait()

	behind, failed := 0, 0
	for _, got := range results {
		cs := byImage[got.image]
		r.Checks++
		if got.err != nil || !strings.HasPrefix(got.remote, "sha256:") {
			failed++
			continue
		}
		local := cs[0].ImageDigest
		if local == got.remote {
			continue
		}
		behind++
		// One finding per image, listing the containers affected.
		var names []string
		for _, c := range cs {
			names = append(names, c.Name)
		}
		managed := wtAll
		for _, c := range cs {
			if c.Watchtower {
				managed = true
			}
		}
		sev := model.SevMedium
		detail := fmt.Sprintf("Running %s, registry has %s. Affects: %s. "+
			"Image updates are how container CVE fixes actually reach you.",
			short(local), short(got.remote), strings.Join(names, ", "))
		if managed && wtPresent {
			sev = model.SevLow
			detail += " Watchtower manages this container and should pull it on its next scheduled run."
		}
		r.Findings = append(r.Findings, model.NewFinding(model.Finding{
			Agent:    a.Name(),
			Rule:     "image-outdated",
			Title:    "Update available for " + got.image,
			Severity: sev,
			Scope:    model.ScopeProject,
			ScopeKey: cs[0].Project,
			Target:   got.image,
			Detail:   detail,
			Fix:      "Pull the new image and re-create the container.",
			FixCmd:   "docker compose -f " + dirOf(cs[0]) + "/docker-compose.yml pull && docker compose -f " + dirOf(cs[0]) + "/docker-compose.yml up -d",
		}))
	}

	if failed > 0 {
		r.Message = fmt.Sprintf("%d images behind, %d unreachable", behind, failed)
	} else {
		r.Message = fmt.Sprintf("%d of %d images behind", behind, len(results))
	}
	if !wtPresent && behind > 0 {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title:    "Automate image updates",
			Why:      fmt.Sprintf("%d images are behind their published version and nothing is pulling them automatically.", behind),
			Action:   "Run watchtower on a schedule, or add a weekly `docker compose pull && up -d` per stack.",
			Scope:    model.ScopeProject,
			Priority: 2,
			Effort:   "medium",
		}))
	}
	return r, nil
}

// watchtowerScope reports whether a watchtower container is running and whether
// it is in opt-in (label) mode or updating everything.
func watchtowerScope(ctx context.Context, timeout time.Duration) (all bool, present bool) {
	out, err := sh(ctx, timeout, "docker", "ps", "--filter", "ancestor=containrrr/watchtower", "--format", "{{.Names}}")
	name := strings.TrimSpace(out)
	if err != nil || name == "" {
		// Fall back to a name match: the image may be a fork or mirror.
		out, err = sh(ctx, timeout, "docker", "ps", "--filter", "name=watchtower", "--format", "{{.Names}}")
		name = strings.TrimSpace(out)
		if err != nil || name == "" {
			return false, false
		}
	}
	name = lines(name)[0]
	envOut, err := sh(ctx, timeout, "docker", "inspect", name, "-f",
		"{{range .Config.Env}}{{println .}}{{end}}")
	if err != nil {
		return true, true
	}
	for _, l := range lines(envOut) {
		if strings.HasPrefix(l, "WATCHTOWER_LABEL_ENABLE=") &&
			strings.EqualFold(strings.TrimPrefix(l, "WATCHTOWER_LABEL_ENABLE="), "true") {
			return false, true // opt-in mode: only labelled containers
		}
	}
	return true, true
}

func short(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}
