package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alminisl/security-bot/internal/model"
)

// SecretScanner looks for credentials sitting in container environments and for
// compose .env files readable by every user on the box.
type SecretScanner struct{}

func (SecretScanner) Name() string  { return "secret-scanner" }
func (SecretScanner) Title() string { return "Secret Scanner" }
func (SecretScanner) Role() string {
	return "Hunts for credentials exposed in container environments and world-readable .env files."
}

// secretKeyHints match env var names that usually carry a credential.
var secretKeyHints = []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "API_KEY",
	"PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "ADMIN_TOKEN"}

// benignKeyHints are names that match the hints above but hold a path, a flag
// or a file reference rather than the secret itself.
var benignKeyHints = []string{"_FILE", "_PATH", "_ENABLED", "_REQUIRED", "FILE__"}

func looksSecret(key string) bool {
	up := strings.ToUpper(key)
	for _, b := range benignKeyHints {
		if strings.Contains(up, b) {
			return false
		}
	}
	for _, h := range secretKeyHints {
		if strings.Contains(up, h) {
			return true
		}
	}
	return false
}

func (a SecretScanner) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	seenDirs := map[string]bool{}
	// Loose files are collected per project and reported once: they share one
	// chmod and one decision.
	loose := map[string][]string{}
	looseModes := map[string]string{}

	for _, c := range env.Containers {
		r.Checks++
		var exposed []string
		for _, kv := range c.Env {
			i := strings.Index(kv, "=")
			if i <= 0 {
				continue
			}
			key, val := kv[:i], kv[i+1:]
			if val == "" || len(val) < 6 {
				continue
			}
			if looksSecret(key) {
				exposed = append(exposed, key)
			}
		}
		if len(exposed) > 0 {
			r.Findings = append(r.Findings, model.NewFinding(model.Finding{
				Agent:    a.Name(),
				Rule:     "secret-in-env",
				Title:    fmt.Sprintf("%d credential(s) in container environment", len(exposed)),
				Severity: model.SevMedium,
				Scope:    model.ScopeProject,
				ScopeKey: c.Project,
				Target:   c.Name,
				Detail: "Environment variables " + truncate(strings.Join(exposed, ", "), 160) +
					" hold plaintext values. Anything that can run `docker inspect` — including the six containers " +
					"with socket access — can read them, and they leak into `docker inspect` output and crash reports.",
				Fix:    "Move these to Docker secrets or a *_FILE variable pointing at a 0600 file outside the compose file.",
				FixCmd: "docker inspect " + c.Name + " -f '{{range .Config.Env}}{{println .}}{{end}}' | grep -iE 'pass|secret|token'",
			}))
		}

		// Check the compose directory's .env permissions once per project.
		dir := c.WorkingDir
		if dir == "" || seenDirs[dir] {
			continue
		}
		seenDirs[dir] = true
		for _, name := range []string{".env", "docker-compose.yml", "compose.yml", "docker-compose.yaml"} {
			p := filepath.Join(dir, name)
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			r.Checks++
			mode := fi.Mode().Perm()
			if mode&0o044 != 0 { // group or world readable
				loose[c.Project] = append(loose[c.Project], p)
				looseModes[p] = fmt.Sprintf("%04o", mode)
			}
		}
	}

	envFileIssues := 0
	for project, files := range loose {
		envFileIssues += len(files)
		sort.Strings(files)
		var desc []string
		for _, f := range files {
			desc = append(desc, filepath.Base(f)+" ("+looseModes[f]+")")
		}
		r.Findings = append(r.Findings, model.NewFinding(model.Finding{
			Agent:    a.Name(),
			Rule:     "env-file-perms",
			Title:    fmt.Sprintf("%d compose file(s) readable by other users", len(files)),
			Severity: model.SevMedium,
			Scope:    model.ScopeProject,
			ScopeKey: project,
			Target:   filepath.Dir(files[0]),
			Detail: "These files usually hold database passwords and API keys, and any local user or service " +
				"account can read them: " + strings.Join(desc, ", ") + ".",
			Fix:      "Restrict them to your user only.",
			FixCmd:   "chmod 600 " + strings.Join(files, " "),
			FixApply: true,
		}))
	}

	if envFileIssues > 0 {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title:    fmt.Sprintf("Lock down %d compose/.env files to mode 600", envFileIssues),
			Why:      "They hold database and admin credentials in plaintext and are currently readable by other local users.",
			Action:   "Apply the per-finding chmod, then confirm nothing else on the box needs group read.",
			Scope:    model.ScopeProject,
			Priority: 2,
			Effort:   "quick",
		}))
	}
	r.Message = fmt.Sprintf("checked %d environments", len(env.Containers))
	return r, nil
}
