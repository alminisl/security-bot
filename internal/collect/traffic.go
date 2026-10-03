package collect

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
	"github.com/alminisl/security-bot/internal/store"
)

// TrafficWatcher reports on network traffic. The actual observation is done by
// Sample, which the dashboard process runs on a ticker — a once-a-day snapshot
// would miss intermittent beaconing entirely. This agent reads the accumulated
// rollups and reports what is new or anomalous.
type TrafficWatcher struct{}

func (TrafficWatcher) Name() string  { return "traffic-watcher" }
func (TrafficWatcher) Title() string { return "Traffic Watcher" }
func (TrafficWatcher) Role() string {
	return "Samples outbound connections continuously and reports new external destinations and per-container volume spikes."
}

const trafficKey = "traffic"

// spikeFloor is the minimum traffic in a window before a multiple of the mean
// is worth reporting. Without it, a container that normally sends 2 KB trips
// the alarm by sending 20 KB.
const spikeFloor = 200 << 20 // 200 MiB

func (a TrafficWatcher) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	add := func(f model.Finding) {
		f.Agent = a.Name()
		f.Scope = model.ScopeTraffic
		f.ScopeKey = trafficKey
		r.Findings = append(r.Findings, model.NewFinding(f))
	}

	t := env.Store.Traffic()

	// If the sampler has never run, take one sample so the tab is not empty,
	// and say plainly that this is a snapshot rather than monitoring.
	if t.Windows == 0 {
		if err := Sample(ctx, env.Store, env.Containers); err != nil {
			r.Unavailable = true
			r.Message = "no traffic data and sampling failed: " + err.Error()
			return r, nil
		}
		t = env.Store.Traffic()
		r.Suggestions = append(r.Suggestions, model.NewSuggestion(model.Suggestion{
			Title: "Run the dashboard continuously to get real traffic monitoring",
			Why: "Traffic is sampled by the `sentinel serve` process every minute. Without it running, each scan " +
				"sees only a single snapshot, and intermittent connections — which is what beaconing looks like — " +
				"will not appear at all.",
			Action:   "Enable the dashboard service so sampling runs around the clock.",
			Cmd:      "systemctl --user enable --now sentinel-web.service",
			Scope:    model.ScopeTraffic,
			ScopeKey: trafficKey,
			Priority: 2,
			Effort:   "quick",
		}))
	}

	// ---- new external destinations ----
	var fresh []*store.FlowStat
	for _, f := range t.Flows {
		if !env.Since.IsZero() && f.First.After(env.Since) {
			fresh = append(fresh, f)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Samples > fresh[j].Samples })

	// Resolve names for the handful we are going to show.
	resolveHosts(ctx, t, fresh, 25)

	for _, f := range fresh {
		r.Flows = append(r.Flows, model.Flow{
			Remote: f.Remote, Port: f.Port, Host: displayHost(f.Host), Proto: f.Proto,
			Samples:   f.Samples,
			FirstSeen: f.First.Format(time.RFC3339),
			LastSeen:  f.Last.Format(time.RFC3339),
			New:       true,
		})
	}
	// Plus the established talkers, for context on the dashboard.
	var regular []*store.FlowStat
	for _, f := range t.Flows {
		if env.Since.IsZero() || !f.First.After(env.Since) {
			regular = append(regular, f)
		}
	}
	sort.Slice(regular, func(i, j int) bool { return regular[i].Samples > regular[j].Samples })
	if len(regular) > 40 {
		regular = regular[:40]
	}
	resolveHosts(ctx, t, regular, 40)
	for _, f := range regular {
		r.Flows = append(r.Flows, model.Flow{
			Remote: f.Remote, Port: f.Port, Host: displayHost(f.Host), Proto: f.Proto,
			Samples:   f.Samples,
			FirstSeen: f.First.Format(time.RFC3339),
			LastSeen:  f.Last.Format(time.RFC3339),
		})
	}

	if len(fresh) > 0 {
		var desc []string
		for i, f := range fresh {
			if i >= 10 {
				break
			}
			label := f.Remote + ":" + f.Port
			if displayHost(f.Host) != "" {
				label += " (" + f.Host + ")"
			}
			desc = append(desc, label)
		}
		// Many new destinations after a quiet period is more interesting than
		// one, but a handful is normal on a host that updates containers.
		sev := model.SevLow
		if len(fresh) > 20 {
			sev = model.SevMedium
		}
		add(model.Finding{
			Rule:     "new-destinations",
			Title:    fmt.Sprintf("%d new external destination(s) since the last scan", len(fresh)),
			Severity: sev,
			Target:   "outbound",
			Detail: "This machine connected to service addresses it had not contacted before: " +
				truncate(strings.Join(desc, ", "), 400) +
				". Most will be CDNs and registries. What you are looking for is a destination that no service " +
				"here has a reason to talk to, especially one contacted at a regular interval. " +
				"Peer-to-peer connections are excluded from this count — they are listed separately on the Traffic tab.",
			Fix:    "Review the list on the Traffic tab; identify anything you cannot account for.",
			FixCmd: "ss -tunp state established",
		})
	}

	// ---- per-container volume ----
	var spikes []string
	for name, u := range t.Usage {
		delta := float64((u.Rx - u.LastRx) + (u.Tx - u.LastTx))
		ct := model.ContainerTraffic{
			Name: name, RxBytes: u.Rx, TxBytes: u.Tx,
			RxDelta: u.Rx - u.LastRx, TxDelta: u.Tx - u.LastTx,
			Baseline: int64(u.MeanDelta),
		}
		if u.MeanDelta > 0 && u.Windows > 5 {
			ct.Spike = delta / u.MeanDelta
			if ct.Spike >= 5 && delta >= spikeFloor {
				spikes = append(spikes, fmt.Sprintf("%s (%s, %.0f× its normal)", name, humanBytes(int64(delta)), ct.Spike))
			}
		}
		r.NetUsage = append(r.NetUsage, ct)
	}
	sort.Slice(r.NetUsage, func(i, j int) bool {
		return r.NetUsage[i].RxBytes+r.NetUsage[i].TxBytes > r.NetUsage[j].RxBytes+r.NetUsage[j].TxBytes
	})

	if len(spikes) > 0 {
		add(model.Finding{
			Rule:     "traffic-spike",
			Title:    fmt.Sprintf("%d container(s) moved far more data than usual", len(spikes)),
			Severity: model.SevMedium,
			Target:   truncate(strings.Join(spikes, "; "), 120),
			Detail: "Compared with their own rolling average: " + truncate(strings.Join(spikes, "; "), 350) +
				". Usually a backup, a sync or a large download. It is also what bulk exfiltration looks like.",
			Fix:    "Confirm what the container was doing. Check its logs around the time of the spike.",
			FixCmd: "docker stats --no-stream",
		})
	}

	// Peer-like endpoints are shown for context, never alerted on.
	var peers []*store.FlowStat
	for _, f := range t.Peers {
		peers = append(peers, f)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Samples > peers[j].Samples })
	if len(peers) > 20 {
		peers = peers[:20]
	}
	for _, f := range peers {
		r.Flows = append(r.Flows, model.Flow{
			Remote: f.Remote, Port: f.Port, Host: displayHost(f.Host), Proto: f.Proto,
			Samples:   f.Samples,
			FirstSeen: f.First.Format(time.RFC3339),
			LastSeen:  f.Last.Format(time.RFC3339),
			Peer:      true,
		})
	}

	r.Checks = len(t.Flows) + len(t.Peers) + len(t.Usage)
	r.Message = fmt.Sprintf("%d service endpoints (%d new), %d recurring peers, %d windows",
		len(t.Flows), len(fresh), len(t.Peers), t.Windows)
	return r, nil
}

// Sample records one observation of current connections and container byte
// counters. Called on a ticker by the dashboard process and once by the agent
// when no data exists yet.
func Sample(ctx context.Context, st *store.Store, containers []model.Container) error {
	t := st.Traffic()
	now := time.Now()

	// Established connections only: listening sockets are the network
	// auditor's job, and we want conversations, not availability.
	out, err := sh(ctx, 20*time.Second, "ss", "-tunH", "state", "established")
	if err != nil {
		return err
	}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		// Netid Recv-Q Send-Q Local:Port Peer:Port
		if len(f) < 5 {
			continue
		}
		proto, peer := f[0], f[4]
		ip, port := splitHostPort(peer)
		if ip == "" || !isExternal(ip) {
			continue // loopback, LAN and tailnet peers are not what this is for
		}
		key := proto + "/" + ip + ":" + port
		// A host running a BitTorrent client contacts thousands of addresses on
		// ephemeral ports, each once. Mixed in with service traffic that churn
		// makes "new destination" meaningless, so the two are tracked apart and
		// only service destinations raise a finding.
		bucket := t.Flows
		if !serviceLike(port) {
			bucket = t.Peers
		}
		fs := bucket[key]
		if fs == nil {
			fs = &store.FlowStat{Proto: proto, Remote: ip, Port: port, First: now}
			bucket[key] = fs
		}
		fs.Samples++
		fs.Last = now
	}

	// Container byte counters. docker stats is the only unprivileged source of
	// per-container network totals.
	if stats, err := sh(ctx, 60*time.Second, "docker", "stats", "--no-stream",
		"--format", "{{.Name}}\t{{.NetIO}}"); err == nil {
		for _, l := range lines(stats) {
			parts := strings.Split(l, "\t")
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			rx, tx := parseNetIO(parts[1])
			u := t.Usage[name]
			if u == nil {
				u = &store.UsageStat{Rx: rx, Tx: tx, LastRx: rx, LastTx: tx}
				t.Usage[name] = u
			}
			// A counter going backwards means the container restarted, so the
			// previous total is not a valid baseline for a delta.
			if rx < u.Rx || tx < u.Tx {
				u.LastRx, u.LastTx = rx, tx
			} else {
				u.LastRx, u.LastTx = u.Rx, u.Tx
			}
			delta := float64((rx - u.LastRx) + (tx - u.LastTx))
			u.Rx, u.Tx = rx, tx
			u.Windows++
			// Running mean, so a spike does not permanently raise the baseline
			// it is measured against.
			if u.Windows == 1 {
				u.MeanDelta = delta
			} else {
				u.MeanDelta += (delta - u.MeanDelta) / float64(min(u.Windows, 60))
			}
		}
	}

	t.Windows++
	t.PruneFlows(14*24*time.Hour, 4000)
	return st.SaveTraffic(t)
}

// servicePorts are destination ports that indicate a connection to a service
// rather than to a peer. Anything else on a high port is treated as peer-like.
var servicePorts = map[string]bool{
	"80": true, "443": true, "8080": true, "8443": true, "53": true, "853": true,
	"22": true, "25": true, "465": true, "587": true, "993": true, "995": true,
	"123": true, "143": true, "993\n": false, "3478": true, "5349": true,
	"1935": true, "5222": true, "5223": true, "9418": true, "11371": true,
}

// serviceLike reports whether a remote port looks like a service endpoint.
// Everything below 1024 is privileged and therefore a service by definition.
func serviceLike(port string) bool {
	if servicePorts[port] {
		return true
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return n > 0 && n < 1024
}

// resolveHosts fills in reverse DNS for the endpoints about to be displayed,
// bounded so a scan is never held up by a slow resolver.
func resolveHosts(ctx context.Context, t *store.TrafficState, flows []*store.FlowStat, limit int) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var res net.Resolver
	for i, f := range flows {
		if i >= limit {
			return
		}
		if f.Host != "" {
			continue
		}
		names, err := res.LookupAddr(rctx, f.Remote)
		if err != nil || len(names) == 0 {
			f.Host = "-" // remember the miss, so it is not retried every scan
			continue
		}
		f.Host = strings.TrimSuffix(names[0], ".")
	}
}

// displayHost hides the sentinel value used to remember a failed lookup.
func displayHost(h string) string {
	if h == "-" {
		return ""
	}
	return h
}

func splitHostPort(s string) (string, string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", ""
	}
	host := strings.Trim(s[:i], "[]")
	// ss reports some sockets in IPv4-mapped form (::ffff:1.2.3.4). Left as-is
	// that is a second key for an endpoint we may already be tracking, and it
	// reads badly in the UI.
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			host = v4.String()
		} else {
			host = ip.String()
		}
	}
	return host, s[i+1:]
}

// isExternal excludes anything that is not a public internet address: private
// ranges, loopback, link-local and the Tailscale CGNAT range.
func isExternal(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// Tailscale uses 100.64.0.0/10, which is CGNAT space and not private by
	// Go's definition.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}

// parseNetIO reads docker stats' "1.2GB / 3.4MB" into bytes.
func parseNetIO(s string) (rx, tx int64) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	return parseSize(parts[0]), parseSize(parts[1])
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Longest suffixes first, or "MB" would match inside "MiB".
	units := []struct {
		suffix string
		mult   float64
	}{
		{"PiB", 1 << 50}, {"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"PB", 1e15}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"KB", 1e3}, {"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0
			}
			return int64(v * u.mult)
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(v)
}

func humanBytes(n int64) string {
	f := float64(n)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
