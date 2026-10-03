package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/alminisl/security-bot/internal/model"
)

// ContainerAuditor reviews how each container is configured: the escape paths,
// the over-broad privileges and the exposure that a CVE scanner never sees.
type ContainerAuditor struct{}

func (ContainerAuditor) Name() string  { return "container-auditor" }
func (ContainerAuditor) Title() string { return "Container Auditor" }
func (ContainerAuditor) Role() string {
	return "Reviews runtime configuration of every container: privileges, capabilities, mounts and port exposure."
}

// dbPorts are container ports that should essentially never be reachable from
// the LAN; exposing them is treated more seriously than a web port.
var dbPorts = map[string]string{
	"5432": "PostgreSQL", "3306": "MySQL/MariaDB", "6379": "Redis",
	"27017": "MongoDB", "5984": "CouchDB", "9200": "Elasticsearch",
	"11211": "Memcached", "5433": "PostgreSQL",
}

// dangerousCaps are capabilities that materially weaken container isolation.
var dangerousCaps = map[string]string{
	"SYS_ADMIN":       "near-root on the host",
	"SYS_PTRACE":      "can inspect and inject into other processes",
	"SYS_MODULE":      "can load kernel modules",
	"NET_ADMIN":       "can reconfigure host networking",
	"DAC_READ_SEARCH": "can bypass file read permission checks",
	"SYS_RAWIO":       "raw I/O access to devices",
}

// sensitiveHostPaths are host locations that should not be writable from a
// container.
var sensitiveHostPaths = []string{"/etc", "/root", "/boot", "/usr", "/bin", "/sbin", "/var/lib/docker"}

// hygiene collects the low-severity configuration gaps that would otherwise
// fire once per container. Reported per project instead: that is the file you
// would edit to fix them, and 114 individual findings bury the few that need
// a reaction today.
type hygiene struct {
	noNewPriv []string
	root      []string
	noMem     []string
	latest    []string
	total     int
}

func (a ContainerAuditor) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	sockets := 0
	agg := map[string]*hygiene{}

	for _, c := range env.Containers {
		key := c.Project
		if agg[key] == nil {
			agg[key] = &hygiene{}
		}
		h := agg[key]
		h.total++
		add := func(f model.Finding) {
			f.Agent = a.Name()
			f.Scope = model.ScopeProject
			f.ScopeKey = key
			f.Target = c.Name
			r.Findings = append(r.Findings, model.NewFinding(f))
		}
		r.Checks += 9

		if c.Privileged {
			add(model.Finding{
				Rule:     "privileged",
				Title:    "Runs in privileged mode",
				Severity: model.SevCritical,
				Detail: "Privileged containers get all capabilities and host device access. " +
					"A compromise here is a host compromise — there is almost no isolation left.",
				Fix:      "Remove `privileged: true` and grant only the specific capabilities needed (e.g. cap_add: [SYS_PTRACE]).",
				FixCmd:   fmt.Sprintf("grep -rn 'privileged' %s", dirOf(c)),
				FixApply: false,
			})
		}

		for _, m := range c.Mounts {
			if strings.Contains(m.Source, "docker.sock") {
				sockets++
				sev := model.SevHigh
				note := "writable"
				if !m.RW {
					sev = model.SevMedium
					note = "read-only"
				}
				add(model.Finding{
					Rule:     "docker-socket",
					Title:    "Mounts the Docker socket (" + note + ")",
					Severity: sev,
					Detail: "Access to /var/run/docker.sock is equivalent to root on the host: " +
						"any process in this container can start a new privileged container mounting /. " +
						"If this container is ever exploited, the whole machine goes with it.",
					Fix: "Put a socket proxy (tecnativa/docker-socket-proxy) in front and grant only the API " +
						"endpoints this app needs, or mount the socket read-only where the app allows it.",
					FixCmd: "docker inspect " + c.Name + " -f '{{range .Mounts}}{{.Source}} {{.RW}}{{\"\\n\"}}{{end}}'",
				})
			}
			if m.RW && m.Type == "bind" {
				for _, p := range sensitiveHostPaths {
					if m.Source == p || strings.HasPrefix(m.Source, p+"/") {
						add(model.Finding{
							Rule:     "sensitive-mount-rw",
							Title:    "Writable bind mount of " + m.Source,
							Severity: model.SevHigh,
							Target:   c.Name + ":" + m.Source,
							Detail: "The container can modify " + m.Source + " on the host (mounted at " +
								m.Destination + "). That is a direct route to host persistence.",
							Fix: "Append `:ro` to the volume so the mount is read-only, or mount a narrower subdirectory.",
						})
						break
					}
				}
			}
		}

		if c.NetworkMode == "host" {
			add(model.Finding{
				Rule:     "host-network",
				Title:    "Uses host networking",
				Severity: model.SevHigh,
				Detail: "With network_mode: host the container shares the host network namespace, " +
					"bypassing Docker's port isolation and firewall rules entirely.",
				Fix: "Switch to a bridge network and publish only the ports required.",
			})
		}

		for _, cap := range c.CapAdd {
			up := strings.ToUpper(strings.TrimPrefix(cap, "CAP_"))
			if why, bad := dangerousCaps[up]; bad {
				add(model.Finding{
					Rule:     "dangerous-cap",
					Title:    "Granted capability " + up,
					Severity: model.SevHigh,
					Target:   c.Name + ":" + up,
					Detail:   "CAP_" + up + " means the container " + why + ".",
					Fix:      "Drop this capability unless the workload genuinely needs it; prefer a narrower one.",
				})
			}
		}

		// Port exposure: 0.0.0.0 means reachable from the whole LAN.
		for _, p := range c.Ports {
			if p.HostIP != "0.0.0.0" && p.HostIP != "" && p.HostIP != "::" {
				continue
			}
			cp := strings.SplitN(p.Container, "/", 2)[0]
			sev := model.SevMedium
			detail := "Published on 0.0.0.0:" + p.HostPort + ", so any host on your LAN can reach it. " +
				"Unless this is meant to be shared, bind it to localhost and reach it through your reverse proxy or Tailscale."
			if svc, isDB := dbPorts[cp]; isDB {
				sev = model.SevHigh
				detail = svc + " is exposed on 0.0.0.0:" + p.HostPort + ". Databases should never be LAN-reachable; " +
					"this is a direct target for credential brute-forcing and known-CVE exploitation."
			}
			add(model.Finding{
				Rule:     "port-exposed",
				Title:    "Port " + p.HostPort + " exposed on all interfaces",
				Severity: sev,
				Target:   c.Name + ":" + p.HostPort,
				Detail:   detail,
				Fix:      "Change the port mapping to `127.0.0.1:" + p.HostPort + ":" + cp + "` in the compose file, then re-create the container.",
				FixCmd:   fmt.Sprintf("grep -rn '%s:' %s", p.HostPort, dirOf(c)),
			})
		}

		hasNoNewPriv := false
		for _, o := range c.SecurityOpt {
			if strings.Contains(o, "no-new-privileges") {
				hasNoNewPriv = true
			}
		}
		if !hasNoNewPriv && !c.Privileged {
			h.noNewPriv = append(h.noNewPriv, c.Name)
		}

		if c.User == "" || c.User == "root" || c.User == "0" || strings.HasPrefix(c.User, "0:") {
			h.root = append(h.root, c.Name)
		}

		if c.MemLimit == 0 {
			h.noMem = append(h.noMem, c.Name)
		}

		if strings.HasSuffix(c.Image, ":latest") {
			h.latest = append(h.latest, c.Name)
		}
	}

	// Emit the aggregated hygiene findings, one per project per rule.
	for project, h := range agg {
		hyg := func(rule, title, detail, fix string, sev model.Severity, names []string) {
			if len(names) == 0 {
				return
			}
			r.Findings = append(r.Findings, model.NewFinding(model.Finding{
				Agent:    a.Name(),
				Rule:     rule,
				Title:    fmt.Sprintf(title, len(names), h.total),
				Severity: sev,
				Scope:    model.ScopeProject,
				ScopeKey: project,
				Target:   project,
				Detail:   detail + " Affects: " + truncate(strings.Join(names, ", "), 240) + ".",
				Fix:      fix,
			}))
		}
		hyg("no-new-privileges", "%d of %d containers allow privilege escalation",
			"Without security_opt no-new-privileges, a process in the container can gain privileges through "+
				"setuid binaries. It is a one-line change per service and rarely breaks anything.",
			"Add `security_opt: [\"no-new-privileges:true\"]` to these services.",
			model.SevLow, h.noNewPriv)
		hyg("runs-as-root", "%d of %d containers run as root",
			"The main process runs as uid 0. Combined with a container escape or a writable mount, root inside "+
				"is a far better starting position for an attacker than an unprivileged user.",
			"Set `user: \"1000:1000\"` where the image supports it (linuxserver.io images use PUID/PGID instead).",
			model.SevLow, h.root)
		hyg("no-mem-limit", "%d of %d containers have no memory limit",
			"An unbounded container can exhaust host memory — through a leak, a traffic spike, or a cryptominer "+
				"dropped by an attacker — and take every other container on the box down with it.",
			"Add `mem_limit` (or deploy.resources.limits) sized to each workload.",
			model.SevInfo, h.noMem)
		hyg("unpinned-tag", "%d of %d containers track :latest",
			"`:latest` makes the running version unpredictable and rollback hard: you cannot tell which build "+
				"you are on, and a re-pull can silently change behaviour.",
			"Pin a major/minor tag (e.g. `redis:7.4`) so updates are deliberate.",
			model.SevLow, h.latest)
	}

	if sockets > 0 {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: fmt.Sprintf("Put a socket proxy in front of the %d containers using docker.sock", sockets),
			Why: "Each one is a root-equivalent path to the host. A proxy lets dozzle read logs and homepage read " +
				"container lists without handing either of them the ability to create containers.",
			Action:   "Deploy tecnativa/docker-socket-proxy and point those containers at it with read-only API scopes.",
			Cmd:      "docker ps --filter volume=/var/run/docker.sock --format '{{.Names}}'",
			Scope:    model.ScopeProject,
			Priority: 1,
			Effort:   "medium",
		}))
	}
	r.Message = fmt.Sprintf("audited %d containers", len(env.Containers))
	return r, nil
}

// dirOf returns the compose directory for a container, for use in fix hints.
func dirOf(c model.Container) string {
	if c.WorkingDir != "" {
		return c.WorkingDir
	}
	return "."
}
