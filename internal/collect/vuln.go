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
		// "Fixable" in Trivy's sense means a patched package version exists —
		// not that a newer image has been published. Those are different
		// situations with different actions, and conflating them produces a
		// critical finding the user cannot act on.
		sev := model.SevHigh
		if crit > 0 {
			sev = model.SevCritical
		}
		detail := fmt.Sprintf("%d critical and %d high fixable CVEs. Affects: %s.", crit, high, strings.Join(names, ", "))
		if len(worst) > 0 {
			detail += " Worst: " + strings.Join(worst, "; ") + "."
		}
		fix := "Pull the latest image — these have fixed package versions available upstream."
		fixCmd := "docker compose -f " + dirOf(byImage[image][0]) + "/docker-compose.yml pull && " +
			"docker compose -f " + dirOf(byImage[image][0]) + "/docker-compose.yml up -d"
		rule := "image-cves"

		switch {
		case env.LocalBuild[image]:
			// Built here, so the base image is the user's to update and this is
			// the most actionable version of this finding.
			rule = "image-cves-local"
			detail += " This image is built on this machine, so its base image is yours to update — " +
				"nothing upstream will fix it for you."
			fix = "Rebuild this image on a current base image, then re-deploy."
			fixCmd = "docker compose -f " + dirOf(byImage[image][0]) + "/docker-compose.yml build --pull && " +
				"docker compose -f " + dirOf(byImage[image][0]) + "/docker-compose.yml up -d"

		case env.UpdatesKnown && env.Unknown[image]:
			// Could not be compared, so claiming either action would be a
			// guess. Keep the severity and say what to try.
			detail += " This image could not be compared against its registry, so whether a newer " +
				"build exists is unknown."
			fix = "Pull to check for a newer image; if it is already current, this is upstream's to patch."

		case env.UpdatesKnown && !env.Behind[image]:
			// Already on the newest published digest: pulling changes nothing.
			// Still worth knowing, but it is not a critical you can clear today.
			rule = "image-cves-upstream"
			if sev == model.SevCritical {
				sev = model.SevHigh
			} else {
				sev = model.SevMedium
			}
			detail += " This container is already running the newest published digest for its tag, " +
				"so pulling will not help — the vulnerable packages are in the image as published. " +
				"Either a newer major or minor tag exists, or this is upstream's to fix."
			fix = "Check whether a newer tag is available (this one is current). If not, this is upstream's " +
				"to patch — decide whether the exposure is acceptable or whether to replace the component."
			fixCmd = "docker buildx imagetools inspect " + image + " --format '{{json .Manifest}}' | head -20"
		}

		r.Findings = append(r.Findings, model.NewFinding(model.Finding{
			Agent:    a.Name(),
			Rule:     rule,
			Title:    fmt.Sprintf("%s has %d critical / %d high CVEs", image, crit, high),
			Severity: sev,
			Scope:    model.ScopeProject,
			ScopeKey: byImage[image][0].Project,
			Target:   image,
			Detail:   detail,
			Fix:      fix,
			FixCmd:   fixCmd,
			Refs:     []string{"https://avd.aquasec.com/"},
		}))
	}
	r.Message = fmt.Sprintf("%d images scanned, %d critical / %d high", len(images), totalCrit, totalHigh)
	return r, nil
}
