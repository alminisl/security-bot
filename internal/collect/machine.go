package collect

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alminisl/security-bot/internal/model"
)

// MachineAuditor covers the host itself: patch level, firewall, SSH exposure
// and the Docker daemon's own configuration.
type MachineAuditor struct{}

func (MachineAuditor) Name() string  { return "machine-auditor" }
func (MachineAuditor) Title() string { return "Machine Auditor" }
func (MachineAuditor) Role() string {
	return "Audits the host: pending security updates, firewall, SSH configuration and the Docker daemon."
}

const machineKey = "machine"

func (a MachineAuditor) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	add := func(f model.Finding) {
		f.Agent = a.Name()
		f.Scope = model.ScopeMachine
		f.ScopeKey = machineKey
		r.Findings = append(r.Findings, model.NewFinding(f))
	}

	// Pending updates. apt-check reports "updates;security-updates" and needs
	// no privileges.
	r.Checks++
	if out, err := sh(ctx, env.Timeout, "/usr/lib/update-notifier/apt-check"); err == nil || out != "" {
		// apt-check writes to stderr; sh returns stdout, so fall back to the
		// stderr-bearing error string when stdout is empty.
		data := out
		if data == "" && err != nil {
			data = err.Error()
		}
		if parts := strings.Split(strings.TrimSpace(data), ";"); len(parts) == 2 {
			total, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			sec, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			if sec > 0 {
				sev := model.SevMedium
				if sec >= 10 {
					sev = model.SevHigh
				}
				add(model.Finding{
					Rule:     "apt-security-updates",
					Title:    fmt.Sprintf("%d security updates pending", sec),
					Severity: sev,
					Target:   "apt",
					Detail: fmt.Sprintf("%d of %d available package updates are security updates. "+
						"Unattended-upgrades handles these on a delay; anything still listed has not been applied yet.", sec, total),
					Fix:      "Apply security updates now.",
					FixCmd:   "sudo apt-get update && sudo apt-get upgrade -y",
					FixApply: false,
				})
			}
		}
	}

	// Reboot required: a patched kernel that is not running is not patched.
	r.Checks++
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		pkgs := ""
		if b, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
			pkgs = truncate(strings.Join(lines(string(b)), ", "), 200)
		}
		add(model.Finding{
			Rule:     "reboot-required",
			Title:    "Reboot required to finish applying updates",
			Severity: model.SevHigh,
			Target:   "kernel",
			Detail: "Updated packages are installed but the running system still uses the old code. " +
				"For kernel and libc updates this means the vulnerability is still live. Pending: " + pkgs,
			Fix:    "Schedule a reboot. With restart policies set, your containers come back on their own.",
			FixCmd: "sudo systemctl reboot",
		})
	}

	// Unattended upgrades.
	r.Checks++
	if out, _ := sh(ctx, env.Timeout, "systemctl", "is-enabled", "unattended-upgrades"); !strings.Contains(out, "enabled") {
		add(model.Finding{
			Rule:     "no-unattended-upgrades",
			Title:    "Automatic security updates are not enabled",
			Severity: model.SevMedium,
			Target:   "unattended-upgrades",
			Detail:   "Without it, host security patches only land when you remember to run apt.",
			Fix:      "Enable unattended-upgrades for the security pocket.",
			FixCmd:   "sudo dpkg-reconfigure --priority=low unattended-upgrades",
		})
	}

	// Firewall. ufw status needs root; fall back to reporting that we cannot
	// tell rather than guessing.
	r.Checks++
	if have("ufw") {
		out, err := sh(ctx, env.Timeout, "sudo", "-n", "ufw", "status")
		switch {
		case err != nil:
			add(model.Finding{
				Rule:     "firewall-unknown",
				Title:    "Firewall state could not be read",
				Severity: model.SevInfo,
				Target:   "ufw",
				Detail: "Reading ufw status needs root and this scan runs unprivileged. " +
					"Note that ufw does not filter Docker's published ports anyway — Docker writes its own iptables rules ahead of ufw.",
				Fix:    "Check manually, and remember that binding containers to 127.0.0.1 is what actually limits exposure.",
				FixCmd: "sudo ufw status verbose",
			})
		case strings.Contains(out, "inactive"):
			add(model.Finding{
				Rule:     "firewall-inactive",
				Title:    "Firewall is inactive",
				Severity: model.SevMedium,
				Target:   "ufw",
				Detail:   "No host firewall is filtering inbound traffic to non-Docker services such as SSH.",
				Fix:      "Enable ufw with a default-deny inbound policy, allowing only what you need.",
				FixCmd:   "sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable",
			})
		}
	}

	// SSH configuration, if readable.
	r.Checks++
	if b, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		cfg := string(b)
		if v := sshdValue(cfg, "PermitRootLogin"); v == "yes" {
			add(model.Finding{
				Rule:     "ssh-root-login",
				Title:    "SSH permits direct root login",
				Severity: model.SevHigh,
				Target:   "sshd",
				Detail:   "PermitRootLogin yes lets an attacker brute-force the one account that needs no privilege escalation.",
				Fix:      "Set `PermitRootLogin no` and use sudo from your own account.",
				FixCmd:   "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
			})
		}
		if v := sshdValue(cfg, "PasswordAuthentication"); v == "yes" {
			add(model.Finding{
				Rule:     "ssh-password-auth",
				Title:    "SSH accepts password authentication",
				Severity: model.SevMedium,
				Target:   "sshd",
				Detail:   "Password auth exposes every account to credential stuffing. Keys do not have that failure mode.",
				Fix:      "Confirm your key works, then set `PasswordAuthentication no`.",
				FixCmd:   "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
			})
		}
	}

	// Docker daemon: live-restore and userns-remap are the two settings worth
	// having on a box running 35 containers.
	r.Checks++
	if b, err := os.ReadFile("/etc/docker/daemon.json"); err != nil {
		add(model.Finding{
			Rule:     "docker-daemon-defaults",
			Title:    "Docker daemon runs with default configuration",
			Severity: model.SevInfo,
			Target:   "dockerd",
			Detail: "No /etc/docker/daemon.json. Worth setting log rotation (containers can fill the disk), " +
				"live-restore, and default ulimits.",
			Fix:    "Create /etc/docker/daemon.json with log-driver rotation and live-restore enabled.",
			FixCmd: "cat /etc/docker/daemon.json",
		})
	} else if !strings.Contains(string(b), "log-opts") {
		add(model.Finding{
			Rule:     "docker-no-log-rotation",
			Title:    "Docker has no log rotation configured",
			Severity: model.SevLow,
			Target:   "dockerd",
			Detail:   "Without max-size/max-file, a chatty container can fill the disk and take every service down.",
			Fix:      "Add log-opts with max-size 10m and max-file 3 to /etc/docker/daemon.json.",
		})
	}

	// Disk headroom: a full disk is an availability incident and breaks logging.
	r.Checks++
	if out, err := sh(ctx, env.Timeout, "df", "--output=pcent,target", "/"); err == nil {
		for _, l := range lines(out)[1:] {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			if pct, err := strconv.Atoi(strings.TrimSuffix(f[0], "%")); err == nil && pct >= 85 {
				sev := model.SevMedium
				if pct >= 95 {
					sev = model.SevHigh
				}
				add(model.Finding{
					Rule:     "disk-pressure",
					Title:    fmt.Sprintf("Root filesystem %d%% full", pct),
					Severity: sev,
					Target:   f[1],
					Detail:   "A full disk stops logging and audit trails, and breaks container writes.",
					Fix:      "Reclaim space; unused Docker images are usually the biggest win.",
					FixCmd:   "docker system df && docker image prune -a",
				})
			}
		}
	}

	// User in the docker group is root-equivalent — worth stating once, plainly.
	r.Checks++
	if out, err := sh(ctx, env.Timeout, "id", "-nG"); err == nil && strings.Contains(" "+out+" ", " docker ") {
		add(model.Finding{
			Rule:     "docker-group-root",
			Title:    "Your user is in the docker group (root-equivalent)",
			Severity: model.SevInfo,
			Target:   "docker group",
			Detail: "Membership of the docker group is equivalent to passwordless root: `docker run -v /:/host` " +
				"gives full host access. Fine for a single-admin box — just know it means your login password is the real boundary.",
			Fix: "Keep the account well protected; consider rootless Docker if this box ever gets other users.",
		})
	}

	r.Message = fmt.Sprintf("%d host checks", r.Checks)
	return r, nil
}

// sshdValue returns the effective value of an sshd_config key, ignoring
// comments. Later directives do not override earlier ones in sshd, so the
// first match wins.
func sshdValue(cfg, key string) string {
	for _, l := range lines(cfg) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && strings.EqualFold(f[0], key) {
			return strings.ToLower(f[1])
		}
	}
	return ""
}
