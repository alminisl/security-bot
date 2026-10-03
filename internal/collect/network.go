package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/alminisl/security-bot/internal/model"
)

// NetworkAuditor looks at what this machine actually offers to the network:
// which sockets listen on a routable address, and what changed since the last
// scan. New listeners nobody deployed are one of the better compromise signals
// available without root.
type NetworkAuditor struct{}

func (NetworkAuditor) Name() string  { return "network-auditor" }
func (NetworkAuditor) Title() string { return "Network Auditor" }
func (NetworkAuditor) Role() string {
	return "Maps every listening socket, flags LAN-reachable services and reports newly opened ports."
}

const networkKey = "network"

// wellKnown labels ports so the dashboard reads clearly.
var wellKnown = map[string]string{
	"22": "SSH", "53": "DNS", "80": "HTTP", "111": "rpcbind", "443": "HTTPS", "631": "CUPS",
	"3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
	"11434": "Ollama", "9090": "Prometheus", "3000": "Grafana", "8080": "HTTP-alt",
	"19999": "Netdata", "32400": "Plex", "3389": "RDP", "5984": "CouchDB",
	"9100": "node-exporter", "9101": "node-exporter", "2049": "NFS",
}

// riskyHostService marks host-level listeners that deserve their own finding
// because they ship with no authentication or expose data directly. Everything
// else gets rolled into one aggregate finding.
var riskyHostService = map[string]struct {
	name   string
	sev    model.Severity
	detail string
}{
	"11434": {"Ollama", model.SevMedium, "Ollama has no authentication. Anyone on the LAN can run inference on your models, enumerate what is loaded, and in some versions pull or delete models."},
	"6379":  {"Redis", model.SevHigh, "Redis has no authentication by default and its CONFIG SET command can be used to write files — a well-known path to remote code execution."},
	"5432":  {"PostgreSQL", model.SevHigh, "A database reachable from the LAN is a direct target for credential brute-forcing and known-CVE exploitation."},
	"3306":  {"MySQL/MariaDB", model.SevHigh, "A database reachable from the LAN is a direct target for credential brute-forcing and known-CVE exploitation."},
	"27017": {"MongoDB", model.SevHigh, "MongoDB has historically shipped without authentication and is routinely found exposed and ransomed."},
	"5984":  {"CouchDB", model.SevHigh, "CouchDB exposes an administrative HTTP API; if it is in admin-party mode anyone on the LAN has full control."},
	"11211": {"Memcached", model.SevHigh, "Memcached has no authentication and is a favoured UDP amplification reflector."},
	"9200":  {"Elasticsearch", model.SevHigh, "Elasticsearch exposes all indexed data over HTTP with no authentication in its default configuration."},
	"111":   {"rpcbind", model.SevMedium, "rpcbind is only needed for NFS. If you are not serving NFS it is attack surface for nothing, and it is usable for UDP amplification."},
	"19999": {"Netdata", model.SevMedium, "Netdata's dashboard is unauthenticated by default and reveals detailed host and container metrics, process names and network connections."},
	"3389":  {"RDP", model.SevMedium, "RDP exposed to the network is a primary target for credential attacks."},
}

type listener struct {
	proto string
	addr  string
	port  string
}

func (a NetworkAuditor) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	add := func(f model.Finding) {
		f.Agent = a.Name()
		f.Scope = model.ScopeNetwork
		f.ScopeKey = networkKey
		r.Findings = append(r.Findings, model.NewFinding(f))
	}

	if !have("ss") {
		r.Unavailable = true
		r.Message = "iproute2 (ss) not available"
		return r, nil
	}

	out, err := sh(ctx, env.Timeout, "ss", "-tulnH")
	if err != nil {
		return r, err
	}

	// Ports Docker published, so the auditor can separate container services
	// from processes running directly on the host.
	dockerPorts := map[string]string{}
	for _, c := range env.Containers {
		for _, p := range c.Ports {
			dockerPorts[p.HostPort] = c.Name
		}
	}

	var ls []listener
	seen := map[string]bool{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		proto, local := f[0], f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, port := local[:i], local[i+1:]
		key := proto + "/" + addr + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		ls = append(ls, listener{proto: proto, addr: addr, port: port})
	}
	r.Checks += len(ls)

	// Current open-port fingerprint, for baseline comparison. A service bound
	// to both 0.0.0.0 and [::] is one service, so dedupe on proto/port rather
	// than on the address, or every dual-stack listener is reported twice.
	var fingerprint []string
	var plain []string
	exposedHost := 0
	seenPort := map[string]bool{}
	for _, l := range ls {
		routable := l.addr == "0.0.0.0" || l.addr == "*" || l.addr == "[::]" || l.addr == "::"
		if !routable {
			continue
		}
		pp := l.proto + "/" + l.port
		if seenPort[pp] {
			continue
		}
		seenPort[pp] = true
		fingerprint = append(fingerprint, pp)
		if _, isDocker := dockerPorts[l.port]; isDocker {
			continue // already reported, with container context, by the container auditor
		}
		exposedHost++

		if risky, ok := riskyHostService[l.port]; ok {
			add(model.Finding{
				Rule:     "risky-host-listener",
				Title:    fmt.Sprintf("%s reachable from the LAN on %s", risky.name, pp),
				Severity: risky.sev,
				Target:   pp,
				Detail:   risky.detail + " This is a host process, not a container.",
				Fix:      "Bind it to 127.0.0.1, or firewall the port, unless it genuinely needs to serve the LAN.",
				FixCmd:   "sudo ss -tulnp | grep ':" + l.port + "'",
			})
			continue
		}
		label := pp
		if n := wellKnown[l.port]; n != "" {
			label = pp + " (" + n + ")"
		}
		plain = append(plain, label)
	}
	sort.Strings(fingerprint)
	sort.Strings(plain)

	// Everything ordinary becomes one finding. A list of 40 individual ports
	// is inventory, not a set of decisions.
	if len(plain) > 0 {
		add(model.Finding{
			Rule:     "host-listeners",
			Title:    fmt.Sprintf("%d host services listen on all interfaces", len(plain)),
			Severity: model.SevLow,
			Target:   "host",
			Detail: "Processes running directly on the host (not in containers) accept connections from any " +
				"network this machine is attached to: " + truncate(strings.Join(plain, ", "), 400) +
				". Each one is reachable by every device on your LAN.",
			Fix:    "Bind anything that does not need LAN access to 127.0.0.1 and reach it over Tailscale instead.",
			FixCmd: "sudo ss -tulnp | grep -E '0\\.0\\.0\\.0|\\[::\\]'",
		})
	}

	// New ports since the last scan.
	if len(env.Base.ListenPorts) > 0 {
		old := map[string]bool{}
		for _, p := range env.Base.ListenPorts {
			old[p] = true
		}
		var added []string
		for _, p := range fingerprint {
			if !old[p] {
				added = append(added, p)
			}
		}
		if len(added) > 0 {
			add(model.Finding{
				Rule:     "new-listening-ports",
				Title:    fmt.Sprintf("%d newly opened port(s) since last scan", len(added)),
				Severity: model.SevMedium,
				Target:   strings.Join(added, ", "),
				Detail: "These ports were not listening at the previous scan: " + strings.Join(added, ", ") +
					". Expected after a deployment. If you did not deploy anything, find out what opened them.",
				Fix:    "Identify the owning process and confirm you started it.",
				FixCmd: "sudo ss -tulnp",
			})
		}
	}
	env.Base.ListenPorts = fingerprint

	// An external view needs a probe from off-box, which this agent cannot do
	// on its own. Say so rather than implying full coverage.
	if !have("nmap") {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: "Install nmap for an off-host view of this machine",
			Why: "This agent sees sockets from the inside. It cannot tell you what your router forwards " +
				"or what a neighbour on the LAN actually reaches.",
			Action:   "Install nmap, then scan this host from another device on the network.",
			Cmd:      "sudo apt-get install -y nmap",
			Scope:    model.ScopeNetwork,
			ScopeKey: networkKey,
			Priority: 3,
			Effort:   "quick",
		}))
	}
	if exposedHost > 0 {
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: "Decide which services genuinely need to be LAN-reachable",
			Why: fmt.Sprintf("%d host services and a number of containers listen on 0.0.0.0. "+
				"Tailscale is already running here, so most of them could be reachable over the tailnet instead.", exposedHost),
			Action:   "Bind everything internal to 127.0.0.1 and reach it via Tailscale or your reverse proxy.",
			Scope:    model.ScopeNetwork,
			ScopeKey: networkKey,
			Priority: 2,
			Effort:   "medium",
		}))
	}

	r.Message = fmt.Sprintf("%d listening sockets, %d host-level on all interfaces", len(ls), exposedHost)
	return r, nil
}
