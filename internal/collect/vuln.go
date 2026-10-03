package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// VulnScanner wraps Trivy for CVE data. Trivy is optional: if it is not
// installed the agent reports itself unavailable and suggests installing it,
// rather than failing the scan.
type VulnScanner struct{}

func (VulnScanner) Name() string  { return "vuln-scanner" }
func (VulnScanner) Title() string { return "Vulnerability Scanner" }
func (VulnScanner) Role() string {
	return "Scans image contents for known CVEs in OS packages and application dependencies (via Trivy)."
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (a VulnScanner) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	if !have("trivy") {
		r.Unavailable = true
		r.Message = "Trivy not installed — no CVE data"
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: "Install Trivy to get CVE coverage",
			Why: "Configuration auditing finds exposure and privilege problems, but it cannot tell you that " +
				"your nextcloud image ships a known-exploited OpenSSL. That is the single biggest gap in this scan.",
			Action:   "Install Trivy, then run a full scan again.",
			Cmd:      "sudo apt-get install -y wget gnupg && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null && echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\" | sudo tee /etc/apt/sources.list.d/trivy.list && sudo apt-get update && sudo apt-get install -y trivy",
			Scope:    model.ScopeProject,
			Priority: 1,
			Effort:   "quick",
		}))
		return r, nil
	}
	if !env.DeepScan {
		r.Message = "skipped (CVE scans run in full scans)"
		return r, nil
	}

	// One scan per unique image, newest-first so a truncated run still covers
	// the images most likely to matter.
	byImage := map[string][]model.Container{}
	for _, c := range env.Containers {
		byImage[c.Image] = append(byImage[c.Image], c)
	}
	images := make([]string, 0, len(byImage))
	for i := range byImage {
		images = append(images, i)
	}
	sort.Strings(images)

	totalCrit, totalHigh := 0, 0
	for _, image := range images {
		select {
		case <-ctx.Done():
			r.Message = fmt.Sprintf("stopped early: %d critical, %d high", totalCrit, totalHigh)
			return r, nil
		default:
		}
		r.Checks++
		out, err := sh(ctx, 4*time.Minute, "trivy", "image", "--quiet", "--scanners", "vuln",
			"--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--format", "json", image)
		if err != nil {
			continue
		}
		var rep trivyReport
		if json.Unmarshal([]byte(out), &rep) != nil {
			continue
		}
		crit, high := 0, 0
		var worst []string
		for _, res := range rep.Results {
			for _, v := range res.Vulnerabilities {
				switch v.Severity {
				case "CRITICAL":
					crit++
					if len(worst) < 5 {
						worst = append(worst, fmt.Sprintf("%s in %s %s → fixed in %s",
							v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion))
					}
				case "HIGH":
					high++
				}
			}
		}
		totalCrit += crit
		totalHigh += high
		if crit == 0 && high == 0 {
			continue
		}
		var names []string
		for _, c := range byImage[image] {
			names = append(names, c.Name)
		}
		sev := model.SevHigh
		if crit > 0 {
			sev = model.SevCritical
		}
		detail := fmt.Sprintf("%d critical and %d high fixable CVEs. Affects: %s.", crit, high, strings.Join(names, ", "))
		if len(worst) > 0 {
			detail += " Worst: " + strings.Join(worst, "; ") + "."
		}
		r.Findings = append(r.Findings, model.NewFinding(model.Finding{
			Agent:    a.Name(),
			Rule:     "image-cves",
			Title:    fmt.Sprintf("%s has %d critical / %d high CVEs", image, crit, high),
			Severity: sev,
			Scope:    model.ScopeProject,
			ScopeKey: byImage[image][0].Project,
			Target:   image,
			Detail:   detail,
			Fix:      "Pull the latest image — all of these have fixed versions available upstream.",
			FixCmd:   "trivy image --severity HIGH,CRITICAL --ignore-unfixed " + image,
			Refs:     []string{"https://avd.aquasec.com/"},
		}))
	}
	r.Message = fmt.Sprintf("%d images scanned, %d critical / %d high", len(images), totalCrit, totalHigh)
	return r, nil
}
