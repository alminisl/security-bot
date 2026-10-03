package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// PackageAuditor inventories everything installed on the machine across every
// package manager in use, and reports what is behind or unsigned. The goal is
// that nothing is installed here without being visible somewhere.
type PackageAuditor struct{}

func (PackageAuditor) Name() string  { return "package-auditor" }
func (PackageAuditor) Title() string { return "Package Auditor" }
func (PackageAuditor) Role() string {
	return "Inventories apt, npm, pipx, snap and Go packages, and reports pending security updates, unsigned repositories and vulnerable project dependencies."
}

const packagesKey = "packages"

func (a PackageAuditor) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	add := func(f model.Finding) {
		f.Agent = a.Name()
		f.Scope = model.ScopePackages
		f.ScopeKey = packagesKey
		r.Findings = append(r.Findings, model.NewFinding(f))
	}
	var sets []model.PackageSet

	// ---- apt ----
	if have("dpkg-query") {
		r.Checks++
		set := model.PackageSet{Manager: "apt", Label: "APT (Debian/Ubuntu)"}
		if out, err := sh(ctx, env.Timeout, "dpkg-query", "-f", "${binary:Package}\\n", "-W"); err == nil {
			set.Count = len(lines(out))
		}
		// Only manually installed packages are listed: the other ~2000 are
		// dependencies pulled in by these, and listing them all is noise.
		manual := map[string]bool{}
		if out, err := sh(ctx, env.Timeout, "apt-mark", "showmanual"); err == nil {
			for _, n := range lines(out) {
				manual[n] = true
			}
		}
		set.Shown = fmt.Sprintf("%d manually installed of %d total", len(manual), set.Count)

		// Versions, and which have an upgrade pending.
		versions := map[string]string{}
		if out, err := sh(ctx, env.Timeout, "dpkg-query", "-f", "${binary:Package}\\t${Version}\\n", "-W"); err == nil {
			for _, l := range lines(out) {
				if p := strings.SplitN(l, "\t", 2); len(p) == 2 {
					versions[strings.SplitN(p[0], ":", 2)[0]] = p[1]
				}
			}
		}
		upgradable, security := aptUpgradable(ctx, env)
		for name := range manual {
			it := model.PackageItem{Name: name, Version: versions[name], Source: "apt"}
			if latest, ok := upgradable[name]; ok {
				it.Outdated = true
				it.Latest = latest
				it.Security = security[name]
				set.Outdated++
			}
			set.Items = append(set.Items, it)
		}
		sort.Slice(set.Items, func(i, j int) bool { return set.Items[i].Name < set.Items[j].Name })
		sets = append(sets, set)

		// Name the packages with security updates: the machine auditor reports
		// that there are N of them, this says which.
		var secNames []string
		for name := range security {
			secNames = append(secNames, name)
		}
		sort.Strings(secNames)
		if len(secNames) > 0 {
			sev := model.SevMedium
			if len(secNames) >= 10 {
				sev = model.SevHigh
			}
			add(model.Finding{
				Rule:     "apt-security-pending",
				Title:    fmt.Sprintf("%d package(s) have security updates pending", len(secNames)),
				Severity: sev,
				Target:   "apt",
				Detail:   "Awaiting a security upgrade: " + truncate(strings.Join(secNames, ", "), 400),
				Fix:      "Apply them, then reboot if the kernel or libc is among them.",
				FixCmd:   "sudo apt-get update && sudo apt-get install --only-upgrade " + strings.Join(firstN(secNames, 20), " "),
			})
		}
	}

	// ---- third-party apt repositories ----
	r.Checks++
	if repos, unsigned := aptRepos(); len(repos) > 0 {
		sev := model.SevLow
		detail := fmt.Sprintf("%d repositories outside the Ubuntu archive are configured: %s. "+
			"Each one can push a package update to this machine, so each is a supply-chain trust decision.",
			len(repos), truncate(strings.Join(repos, ", "), 350))
		if len(unsigned) > 0 {
			sev = model.SevMedium
			detail += " Unsigned or blindly trusted: " + strings.Join(unsigned, ", ") +
				" — packages from these are not cryptographically verified."
		}
		add(model.Finding{
			Rule:     "third-party-repos",
			Title:    fmt.Sprintf("%d third-party package repositories", len(repos)),
			Severity: sev,
			Target:   "/etc/apt/sources.list.d",
			Detail:   detail,
			Fix:      "Remove repositories you no longer use, and make sure each remaining one is signed with a pinned key.",
			FixCmd:   "grep -rsE 'trusted=yes|^deb ' /etc/apt/sources.list.d/ | head -40",
		})
	}

	// ---- npm global ----
	if have("npm") {
		r.Checks++
		if set, ok := npmGlobal(ctx, env); ok {
			sets = append(sets, set)
			if set.Outdated > 0 {
				add(model.Finding{
					Rule:     "npm-global-outdated",
					Title:    fmt.Sprintf("%d global npm package(s) outdated", set.Outdated),
					Severity: model.SevLow,
					Target:   "npm -g",
					Detail: "Globally installed CLI tools run with your full user privileges and are rarely " +
						"updated once installed. " + outdatedList(set),
					Fix:    "Update them, or uninstall the ones you no longer use.",
					FixCmd: "npm update -g",
				})
			}
		}
	}

	// ---- pipx ----
	if have("pipx") {
		r.Checks++
		if set, ok := pipxList(ctx, env); ok {
			sets = append(sets, set)
		}
	}

	// ---- snap ----
	if have("snap") {
		r.Checks++
		if set, ok := snapList(ctx, env); ok {
			sets = append(sets, set)
			if set.Outdated > 0 {
				add(model.Finding{
					Rule:     "snap-outdated",
					Title:    fmt.Sprintf("%d snap(s) have updates available", set.Outdated),
					Severity: model.SevLow,
					Target:   "snap",
					Detail:   "Snaps usually auto-refresh; any still listed has not taken the update. " + outdatedList(set),
					Fix:      "Refresh them.",
					FixCmd:   "sudo snap refresh",
				})
			}
		}
	}

	// ---- Go binaries ----
	r.Checks++
	if set, ok := goBins(); ok {
		sets = append(sets, set)
	}

	// ---- project dependencies ----
	if env.DeepScan && have("npm") {
		r.Checks++
		findings, set := auditNodeProjects(ctx, env)
		if set.Count > 0 {
			sets = append(sets, set)
		}
		for _, f := range findings {
			add(f)
		}
	}

	r.Inventory = sets

	total := 0
	for _, s := range sets {
		total += s.Count
	}
	r.Message = fmt.Sprintf("%d packages across %d managers", total, len(sets))

	if !have("trivy") {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: "Install Trivy to scan installed packages for CVEs, not just updates",
			Why: "This agent can tell you a package is behind. It cannot tell you that the version you are " +
				"running has a known exploited vulnerability. `trivy fs /` covers apt, npm and Python packages at once.",
			Action:   "Install Trivy, then a full scan will include host package CVEs.",
			Scope:    model.ScopePackages,
			ScopeKey: packagesKey,
			Priority: 2,
			Effort:   "quick",
		}))
	}
	return r, nil
}

// aptUpgradable returns package -> candidate version, and which of those come
// from a security pocket.
func aptUpgradable(ctx context.Context, env *Env) (map[string]string, map[string]bool) {
	up := map[string]string{}
	sec := map[string]bool{}
	out, err := sh(ctx, 60*time.Second, "apt", "list", "--upgradable")
	if err != nil && out == "" {
		return up, sec
	}
	for _, l := range lines(out) {
		// Format: name/pocket version arch [upgradable from: old]
		if !strings.Contains(l, "/") || !strings.Contains(l, "upgradable") {
			continue
		}
		slash := strings.Index(l, "/")
		name := l[:slash]
		rest := l[slash+1:]
		f := strings.Fields(rest)
		if len(f) < 2 {
			continue
		}
		up[name] = f[1]
		if strings.Contains(strings.ToLower(f[0]), "security") {
			sec[name] = true
		}
	}
	return up, sec
}

// aptRepos lists configured third-party repositories and those that are not
// cryptographically verified.
func aptRepos() (repos []string, unsigned []string) {
	dir := "/etc/apt/sources.list.d"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".list" && ext != ".sources" {
			continue
		}
		repos = append(repos, strings.TrimSuffix(name, ext))
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		body := string(b)
		trusted := strings.Contains(body, "trusted=yes")
		// A .sources file should carry Signed-By; a .list entry should have
		// signed-by= in its options.
		signed := strings.Contains(body, "Signed-By") || strings.Contains(body, "signed-by")
		if trusted || !signed {
			unsigned = append(unsigned, strings.TrimSuffix(name, ext))
		}
	}
	sort.Strings(repos)
	sort.Strings(unsigned)
	return repos, unsigned
}

func npmGlobal(ctx context.Context, env *Env) (model.PackageSet, bool) {
	set := model.PackageSet{Manager: "npm-global", Label: "npm (global)"}
	out, err := sh(ctx, 60*time.Second, "npm", "ls", "-g", "--depth=0", "--json")
	if err != nil && out == "" {
		return set, false
	}
	var parsed struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal([]byte(out), &parsed) != nil {
		return set, false
	}
	for name, d := range parsed.Dependencies {
		set.Items = append(set.Items, model.PackageItem{Name: name, Version: d.Version, Source: "npm"})
	}
	set.Count = len(set.Items)

	// Outdated check reaches the registry, so only in a full scan.
	if env.DeepScan {
		if o, _ := sh(ctx, 90*time.Second, "npm", "outdated", "-g", "--json"); o != "" {
			var od map[string]struct {
				Current string `json:"current"`
				Latest  string `json:"latest"`
			}
			if json.Unmarshal([]byte(o), &od) == nil {
				for i := range set.Items {
					if e, ok := od[set.Items[i].Name]; ok && e.Latest != "" && e.Latest != e.Current {
						set.Items[i].Outdated = true
						set.Items[i].Latest = e.Latest
						set.Outdated++
					}
				}
			}
		}
	}
	sort.Slice(set.Items, func(i, j int) bool { return set.Items[i].Name < set.Items[j].Name })
	set.Shown = fmt.Sprintf("%d packages", set.Count)
	return set, true
}

func pipxList(ctx context.Context, env *Env) (model.PackageSet, bool) {
	set := model.PackageSet{Manager: "pipx", Label: "pipx (Python CLIs)"}
	out, err := sh(ctx, 60*time.Second, "pipx", "list", "--short")
	if err != nil && out == "" {
		return set, false
	}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		set.Items = append(set.Items, model.PackageItem{Name: f[0], Version: f[1], Source: "pipx"})
	}
	set.Count = len(set.Items)
	set.Shown = fmt.Sprintf("%d packages", set.Count)
	return set, set.Count > 0
}

func snapList(ctx context.Context, env *Env) (model.PackageSet, bool) {
	set := model.PackageSet{Manager: "snap", Label: "snap"}
	out, err := sh(ctx, 60*time.Second, "snap", "list")
	if err != nil && out == "" {
		return set, false
	}
	ls := lines(out)
	if len(ls) > 1 {
		for _, l := range ls[1:] {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			pub := ""
			if len(f) >= 5 {
				pub = f[4]
			}
			set.Items = append(set.Items, model.PackageItem{Name: f[0], Version: f[1], Source: pub})
		}
	}
	set.Count = len(set.Items)
	set.Shown = fmt.Sprintf("%d snaps", set.Count)

	if env.DeepScan {
		if o, _ := sh(ctx, 90*time.Second, "snap", "refresh", "--list"); o != "" {
			pending := map[string]string{}
			for _, l := range lines(o)[1:] {
				f := strings.Fields(l)
				if len(f) >= 2 {
					pending[f[0]] = f[1]
				}
			}
			for i := range set.Items {
				if v, ok := pending[set.Items[i].Name]; ok {
					set.Items[i].Outdated = true
					set.Items[i].Latest = v
					set.Outdated++
				}
			}
		}
	}
	return set, set.Count > 0
}

func goBins() (model.PackageSet, bool) {
	set := model.PackageSet{Manager: "go", Label: "Go binaries"}
	home, err := os.UserHomeDir()
	if err != nil {
		return set, false
	}
	dir := filepath.Join(home, "go", "bin")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return set, false
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		it := model.PackageItem{Name: e.Name(), Source: dir}
		if fi, err := e.Info(); err == nil {
			it.Version = fi.ModTime().Format("2006-01-02")
		}
		set.Items = append(set.Items, it)
	}
	set.Count = len(set.Items)
	set.Shown = fmt.Sprintf("%d binaries (version column is install date)", set.Count)
	return set, set.Count > 0
}

// auditNodeProjects runs `npm audit` against every project with a lockfile.
// Without a lockfile npm cannot audit offline, so those are skipped rather
// than installed — this tool does not mutate your projects.
func auditNodeProjects(ctx context.Context, env *Env) ([]model.Finding, model.PackageSet) {
	set := model.PackageSet{Manager: "npm-projects", Label: "npm (projects)"}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, set
	}
	locks := findLockfiles(home, 4, 40)
	var out []model.Finding
	for _, dir := range locks {
		select {
		case <-ctx.Done():
			return out, set
		default:
		}
		raw, _ := sh(ctx, 90*time.Second, "npm", "audit", "--package-lock-only",
			"--audit-level=high", "--json", "--prefix", dir)
		if raw == "" {
			continue
		}
		var rep struct {
			Metadata struct {
				Vulnerabilities map[string]int `json:"vulnerabilities"`
			} `json:"metadata"`
		}
		if json.Unmarshal([]byte(raw), &rep) != nil {
			continue
		}
		v := rep.Metadata.Vulnerabilities
		crit, high := v["critical"], v["high"]
		set.Count++
		name := filepath.Base(dir)
		set.Items = append(set.Items, model.PackageItem{
			Name:     name,
			Version:  fmt.Sprintf("%d critical, %d high", crit, high),
			Source:   dir,
			Outdated: crit+high > 0,
		})
		if crit+high == 0 {
			continue
		}
		set.Outdated++
		sev := model.SevMedium
		if crit > 0 {
			sev = model.SevHigh
		}
		out = append(out, model.NewFinding(model.Finding{
			Agent:    "package-auditor",
			Rule:     "npm-project-vulns",
			Title:    fmt.Sprintf("%s: %d critical / %d high dependency advisories", name, crit, high),
			Severity: sev,
			Scope:    model.ScopePackages,
			ScopeKey: packagesKey,
			Target:   dir,
			Detail: "npm audit reports known advisories in this project's dependency tree. " +
				"These matter most if the project is deployed or runs untrusted input.",
			Fix:    "Review and apply the fixes npm proposes.",
			FixCmd: "npm audit fix --prefix " + dir,
		}))
	}
	set.Shown = fmt.Sprintf("%d projects with a lockfile", set.Count)
	return out, set
}

// findLockfiles walks the home directory for package-lock.json, skipping
// node_modules and hidden trees, bounded in depth and count.
func findLockfiles(root string, maxDepth, limit int) []string {
	var out []string
	rootDepth := strings.Count(root, string(os.PathSeparator))
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if len(out) >= limit {
			return filepath.SkipAll
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" ||
				name == "vendor" || name == "dist") {
				return filepath.SkipDir
			}
			if strings.Count(path, string(os.PathSeparator))-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "package-lock.json" {
			out = append(out, filepath.Dir(path))
		}
		return nil
	})
	return out
}

func outdatedList(set model.PackageSet) string {
	var names []string
	for _, it := range set.Items {
		if it.Outdated {
			s := it.Name
			if it.Latest != "" {
				s += " → " + it.Latest
			}
			names = append(names, s)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "Outdated: " + truncate(strings.Join(names, ", "), 300) + "."
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
