package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// DeviceAuditor covers the other machines that can reach this one: tailnet
// peers and devices on the local network. A device you forgot about is still a
// device that holds access.
type DeviceAuditor struct{}

func (DeviceAuditor) Name() string  { return "device-auditor" }
func (DeviceAuditor) Title() string { return "Device Auditor" }
func (DeviceAuditor) Role() string {
	return "Audits tailnet peers and local network devices: stale access, key expiry, exit nodes and unknown hosts."
}

const devicesKey = "devices"

// staleAfter is how long a tailnet device can be offline before its continued
// access is worth questioning.
const staleAfter = 30 * 24 * time.Hour

type tsStatus struct {
	Self *tsPeer            `json:"Self"`
	Peer map[string]*tsPeer `json:"Peer"`
}

type tsPeer struct {
	HostName       string     `json:"HostName"`
	DNSName        string     `json:"DNSName"`
	OS             string     `json:"OS"`
	TailscaleIPs   []string   `json:"TailscaleIPs"`
	Online         bool       `json:"Online"`
	LastSeen       time.Time  `json:"LastSeen"`
	KeyExpiry      *time.Time `json:"KeyExpiry"`
	ExitNodeOption bool       `json:"ExitNodeOption"`
	ExitNode       bool       `json:"ExitNode"`
	Tags           []string   `json:"Tags"`
}

func (a DeviceAuditor) Run(ctx context.Context, env *Env) (Result, error) {
	var r Result
	add := func(f model.Finding) {
		f.Agent = a.Name()
		f.Scope = model.ScopeNetwork
		f.ScopeKey = devicesKey
		r.Findings = append(r.Findings, model.NewFinding(f))
	}

	tailnet := a.tailnet(ctx, env, add)
	lan := a.lan(ctx, env, add)
	r.Devices = append(tailnet, lan...)

	// Flag devices that were not in the baseline.
	known := map[string]bool{}
	for _, d := range env.Base.Devices {
		known[d] = true
	}
	first := len(env.Base.Devices) == 0
	var nowKeys []string
	var fresh []string
	for i := range r.Devices {
		key := r.Devices[i].Source + "/" + r.Devices[i].Addr
		nowKeys = append(nowKeys, key)
		if !first && !known[key] {
			r.Devices[i].New = true
			fresh = append(fresh, r.Devices[i].Name+" ("+r.Devices[i].Addr+")")
		}
	}
	sort.Strings(nowKeys)
	env.Base.Devices = nowKeys

	if len(fresh) > 0 {
		add(model.Finding{
			Rule:     "new-device",
			Title:    fmt.Sprintf("%d new device(s) on your networks", len(fresh)),
			Severity: model.SevMedium,
			Target:   truncate(strings.Join(fresh, ", "), 120),
			Detail: "These devices were not present at the last scan: " + truncate(strings.Join(fresh, ", "), 300) +
				". Expected if you added a device; worth identifying if you did not.",
			Fix: "Identify each one. On the tailnet, remove devices you do not recognise from the admin console.",
		})
	}

	r.Checks += len(r.Devices)
	r.Message = fmt.Sprintf("%d tailnet peers, %d local devices", len(tailnet), len(lan))
	if len(r.Devices) == 0 {
		r.Unavailable = true
		r.Message = "no device sources available (tailscale absent, no scanner installed)"
	}
	return r, nil
}

// tailnet reads `tailscale status --json`, which needs no privileges.
func (a DeviceAuditor) tailnet(ctx context.Context, env *Env, add func(model.Finding)) []model.Device {
	if !have("tailscale") {
		return nil
	}
	out, err := sh(ctx, env.Timeout, "tailscale", "status", "--json")
	if err != nil || out == "" {
		return nil
	}
	var st tsStatus
	if json.Unmarshal([]byte(out), &st) != nil {
		return nil
	}

	var devices []model.Device
	var stale []string
	var exitNodes []string
	var noExpiry []string
	now := time.Now()

	consider := func(p *tsPeer, self bool) {
		if p == nil || p.HostName == "" {
			return
		}
		addr := ""
		if len(p.TailscaleIPs) > 0 {
			addr = p.TailscaleIPs[0]
		}
		// Phones and tablets often report "localhost" as their hostname; the
		// tailnet DNS name is what the admin console actually shows.
		name := p.HostName
		if name == "" || strings.EqualFold(name, "localhost") {
			if dns := strings.SplitN(p.DNSName, ".", 2)[0]; dns != "" {
				name = dns
			}
		}
		d := model.Device{
			Name:   name,
			Addr:   addr,
			OS:     p.OS,
			Source: "tailnet",
			Online: p.Online || self,
		}
		if !p.LastSeen.IsZero() {
			d.LastSeen = p.LastSeen.Format(time.RFC3339)
		}
		var notes []string
		if self {
			notes = append(notes, "this host")
		}
		if p.ExitNodeOption {
			notes = append(notes, "offers exit node")
			if !self {
				exitNodes = append(exitNodes, p.HostName)
			}
		}
		if p.KeyExpiry == nil {
			if !self {
				noExpiry = append(noExpiry, p.HostName)
			}
			notes = append(notes, "key never expires")
		} else if p.KeyExpiry.Before(now.Add(14 * 24 * time.Hour)) {
			notes = append(notes, "key expires "+p.KeyExpiry.Format("2006-01-02"))
		}
		if !self && !p.Online && !p.LastSeen.IsZero() && now.Sub(p.LastSeen) > staleAfter {
			days := int(now.Sub(p.LastSeen).Hours() / 24)
			notes = append(notes, fmt.Sprintf("offline %dd", days))
			stale = append(stale, fmt.Sprintf("%s (%dd)", p.HostName, days))
		}
		d.Note = strings.Join(notes, ", ")
		devices = append(devices, d)
	}

	consider(st.Self, true)
	keys := make([]string, 0, len(st.Peer))
	for k := range st.Peer {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		consider(st.Peer[k], false)
	}

	if len(stale) > 0 {
		add(model.Finding{
			Rule:     "stale-tailnet-device",
			Title:    fmt.Sprintf("%d tailnet device(s) offline for over a month but still authorised", len(stale)),
			Severity: model.SevMedium,
			Target:   "tailnet",
			Detail: "Each of these still holds a key that can reach this machine over the tailnet: " +
				strings.Join(stale, ", ") + ". A lost or decommissioned device with live credentials is " +
				"access you are not aware of.",
			Fix:    "Remove devices you no longer use from the Tailscale admin console.",
			FixCmd: "tailscale status",
		})
	}
	if len(noExpiry) > 0 {
		add(model.Finding{
			Rule:     "tailnet-key-no-expiry",
			Title:    fmt.Sprintf("%d tailnet device(s) have key expiry disabled", len(noExpiry)),
			Severity: model.SevLow,
			Target:   "tailnet",
			Detail: "Key expiry is switched off for: " + strings.Join(noExpiry, ", ") +
				". Those devices never need to re-authenticate, so a compromised key stays valid indefinitely.",
			Fix: "Re-enable key expiry for these devices in the admin console unless they are unattended servers.",
		})
	}
	if len(exitNodes) > 0 {
		add(model.Finding{
			Rule:     "tailnet-exit-nodes",
			Title:    fmt.Sprintf("%d tailnet device(s) offer exit-node routing", len(exitNodes)),
			Severity: model.SevInfo,
			Target:   strings.Join(exitNodes, ", "),
			Detail: "These peers advertise themselves as exit nodes: " + strings.Join(exitNodes, ", ") +
				". Traffic routed through an exit node is visible to whoever controls it.",
			Fix: "Confirm you control each one.",
		})
	}
	return devices
}

// lan discovers local devices. The ARP cache is readable unprivileged but on a
// Docker host it is mostly bridge interfaces, so an active sweep is needed for
// a real inventory — and that needs a scanner installed.
func (a DeviceAuditor) lan(ctx context.Context, env *Env, add func(model.Finding)) []model.Device {
	var devices []model.Device

	// Which interface actually faces the LAN, so Docker bridges are excluded.
	lanIface, lanCIDR := primaryInterface()

	out, err := sh(ctx, env.Timeout, "ip", "neigh")
	if err == nil {
		for _, l := range lines(out) {
			f := strings.Fields(l)
			if len(f) < 3 {
				continue
			}
			ip, dev := f[0], ""
			mac := ""
			for i := 1; i < len(f)-1; i++ {
				if f[i] == "dev" {
					dev = f[i+1]
				}
				if f[i] == "lladdr" {
					mac = f[i+1]
				}
			}
			if lanIface != "" && dev != lanIface {
				continue // a Docker bridge neighbour, not a LAN device
			}
			if mac == "" {
				continue
			}
			devices = append(devices, model.Device{
				Name:   ip,
				Addr:   ip,
				MAC:    mac,
				Source: "arp",
				Online: true,
				Note:   "seen in ARP cache on " + dev,
			})
		}
	}

	// Active sweep, when a scanner is available.
	switch {
	case have("nmap") && lanCIDR != "":
		if swept := nmapSweep(ctx, lanCIDR); len(swept) > 0 {
			devices = mergeDevices(devices, swept)
		}
	case have("arp-scan") && lanIface != "":
		if out, err := sh(ctx, 90*time.Second, "arp-scan", "--localnet", "--interface="+lanIface); err == nil {
			devices = mergeDevices(devices, parseArpScan(out))
		}
	default:
		add(model.Finding{
			Rule:     "no-lan-discovery",
			Title:    "Local network discovery is not available",
			Severity: model.SevInfo,
			Target:   "lan",
			Detail: "Without nmap or arp-scan this agent only sees devices already in the ARP cache, which on a " +
				"Docker host is mostly bridge interfaces. It cannot tell you what else is on your LAN or alert " +
				"you when something new appears.",
			Fix:    "Install nmap to enable an active sweep of your local subnet.",
			FixCmd: "sudo apt-get install -y nmap",
		})
	}
	return devices
}

// primaryInterface returns the interface and CIDR facing the default route.
func primaryInterface() (iface, cidr string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, in := range ifaces {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Docker bridges and virtual interfaces are not the LAN.
		if strings.HasPrefix(in.Name, "docker") || strings.HasPrefix(in.Name, "br-") ||
			strings.HasPrefix(in.Name, "veth") || strings.HasPrefix(in.Name, "tailscale") ||
			strings.HasPrefix(in.Name, "wg") || strings.HasPrefix(in.Name, "tun") {
			continue
		}
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || !ipn.IP.IsPrivate() {
				continue
			}
			return in.Name, ipn.String()
		}
	}
	return "", ""
}

// nmapSweep runs an unprivileged host-discovery sweep: no port scanning, just
// which addresses answer.
func nmapSweep(ctx context.Context, cidr string) []model.Device {
	out, err := sh(ctx, 3*time.Minute, "nmap", "-sn", "-n", "--host-timeout", "5s", cidr)
	if err != nil && out == "" {
		return nil
	}
	var devices []model.Device
	var cur string
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "Nmap scan report for ") {
			cur = strings.TrimPrefix(l, "Nmap scan report for ")
			devices = append(devices, model.Device{
				Name: cur, Addr: cur, Source: "sweep", Online: true, Note: "answered a ping sweep",
			})
		}
		if strings.HasPrefix(l, "MAC Address:") && len(devices) > 0 {
			f := strings.Fields(l)
			if len(f) >= 3 {
				devices[len(devices)-1].MAC = f[2]
			}
			if i := strings.Index(l, "("); i > 0 {
				vendor := strings.Trim(l[i:], "()")
				devices[len(devices)-1].Note = "vendor: " + vendor
			}
		}
	}
	return devices
}

func parseArpScan(out string) []model.Device {
	var devices []model.Device
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.Contains(f[0], ".") || !strings.Contains(f[1], ":") {
			continue
		}
		d := model.Device{Name: f[0], Addr: f[0], MAC: f[1], Source: "sweep", Online: true}
		if len(f) > 2 {
			d.Note = "vendor: " + strings.Join(f[2:], " ")
		}
		devices = append(devices, d)
	}
	return devices
}

// mergeDevices prefers richer entries while keeping one row per address.
func mergeDevices(base, extra []model.Device) []model.Device {
	byAddr := map[string]model.Device{}
	var order []string
	for _, d := range append(base, extra...) {
		if prev, ok := byAddr[d.Addr]; ok {
			if prev.MAC == "" {
				prev.MAC = d.MAC
			}
			if prev.Note == "" || strings.HasPrefix(prev.Note, "seen in ARP") {
				prev.Note = d.Note
			}
			byAddr[d.Addr] = prev
			continue
		}
		byAddr[d.Addr] = d
		order = append(order, d.Addr)
	}
	sort.Strings(order)
	out := make([]model.Device, 0, len(order))
	for _, a := range order {
		out = append(out, byAddr[a])
	}
	return out
}
