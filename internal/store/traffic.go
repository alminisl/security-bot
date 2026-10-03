package store

import (
	"sort"
	"sync"
	"time"
)

// TrafficState is the rolling record the traffic sampler maintains. It lives in
// its own file because it is written every sampling interval, far more often
// than a scan.
type TrafficState struct {
	UpdatedAt time.Time `json:"updatedAt"`
	Windows   int       `json:"windows"` // sampling runs recorded
	// Flows holds connections to recognisable service ports. Peers holds
	// everything else — overwhelmingly BitTorrent churn on this kind of host —
	// kept separately so it can be displayed without drowning the signal.
	Flows map[string]*FlowStat  `json:"flows"`
	Peers map[string]*FlowStat  `json:"peers"`
	Usage map[string]*UsageStat `json:"usage"`
}

// FlowStat is one remote endpoint this machine has talked to.
type FlowStat struct {
	Proto   string    `json:"proto"`
	Remote  string    `json:"remote"`
	Port    string    `json:"port"`
	Host    string    `json:"host,omitempty"`
	Samples int       `json:"samples"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// Still too many: drop the least-seen endpoints.

// UsageStat tracks a container's cumulative byte counters and the mean change
// per sampling window, which is what makes a spike detectable.
type UsageStat struct {
	Rx        int64   `json:"rx"`
	Tx        int64   `json:"tx"`
	LastRx    int64   `json:"lastRx"`
	LastTx    int64   `json:"lastTx"`
	Windows   int     `json:"windows"`
	MeanDelta float64 `json:"meanDelta"` // bytes per window, rx+tx
}

// trafficMu guards the file: the sampler writes while a scan may read.
var trafficMu sync.Mutex

func (s *Store) Traffic() *TrafficState {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	t := &TrafficState{
		Flows: map[string]*FlowStat{},
		Peers: map[string]*FlowStat{},
		Usage: map[string]*UsageStat{},
	}
	_ = s.readJSON("traffic.json", t)
	if t.Flows == nil {
		t.Flows = map[string]*FlowStat{}
	}
	if t.Peers == nil {
		t.Peers = map[string]*FlowStat{}
	}
	if t.Usage == nil {
		t.Usage = map[string]*UsageStat{}
	}
	return t
}

func (s *Store) SaveTraffic(t *TrafficState) error {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	t.UpdatedAt = time.Now()
	return s.writeJSON("traffic.json", t)
}

// PruneFlows drops endpoints not seen for a while, so the file does not grow
// without bound on a busy host. Peers are pruned far harder: a torrent client
// contacts thousands of addresses once each, and only the ones that recur are
// worth keeping.
func (t *TrafficState) PruneFlows(olderThan time.Duration, max int) {
	cutoff := time.Now().Add(-olderThan)

	for k, f := range t.Flows {
		if f.Last.Before(cutoff) {
			delete(t.Flows, k)
		}
	}
	// Peers: keep only the ones that recur. The single-sample test must not
	// apply immediately, or a peer is deleted on the sample after the one that
	// first saw it and can never reach two — which kept this bucket
	// permanently empty.
	now := time.Now()
	peerCutoff := now.Add(-48 * time.Hour)
	graceCutoff := now.Add(-2 * time.Hour)
	for k, f := range t.Peers {
		stale := f.Last.Before(peerCutoff)
		oneOff := f.Samples < 2 && f.First.Before(graceCutoff)
		if stale || oneOff {
			delete(t.Peers, k)
		}
	}
	pruneMap(t.Peers, 300)
	pruneMap(t.Flows, max)
}

// pruneMap keeps the most frequently seen entries.
func pruneMap(m map[string]*FlowStat, max int) {
	if len(m) <= max {
		return
	}
	// Still too many: drop the least-seen endpoints.
	type kv struct {
		k string
		n int
	}
	all := make([]kv, 0, len(m))
	for k, f := range m {
		all = append(all, kv{k, f.Samples})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n < all[j].n })
	for _, e := range all[:len(all)-max] {
		delete(m, e.k)
	}
}
