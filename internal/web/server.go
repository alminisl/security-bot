// Package web serves the dashboard. The UI is a single embedded page polling a
// small JSON API, so the binary stays self-contained.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/alminisl/security-bot/internal/audit"
	"github.com/alminisl/security-bot/internal/model"
	"github.com/alminisl/security-bot/internal/notify"
	"github.com/alminisl/security-bot/internal/store"
)

//go:embed assets
var assetsFS embed.FS

type Server struct {
	store    *store.Store
	opts     audit.Options
	log      *log.Logger
	fixes    bool // allow applying fixes from the UI
	sinks    []notify.Sink
	mu       sync.Mutex
	running  bool
	lastErr  string
	progress string
}

func NewServer(st *store.Store, opts audit.Options, lg *log.Logger, allowFixes bool, sinks []notify.Sink) *Server {
	return &Server{store: st, opts: opts, log: lg, fixes: allowFixes, sinks: sinks}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/fix", s.handleFix)
	return mux
}

type stateResponse struct {
	Scan     *model.Scan          `json:"scan"`
	History  []model.HistoryPoint `json:"history"`
	Running  bool                 `json:"running"`
	Progress string               `json:"progress,omitempty"`
	Error    string               `json:"error,omitempty"`
	Fixes    bool                 `json:"fixesEnabled"`
	Now      time.Time            `json:"now"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.Latest()
	s.mu.Lock()
	resp := stateResponse{
		Scan:     sc,
		History:  s.store.History(),
		Running:  s.running,
		Progress: s.progress,
		Error:    s.lastErr,
		Fixes:    s.fixes,
		Now:      time.Now(),
	}
	s.mu.Unlock()
	if err != nil && sc == nil {
		resp.Error = "no scan yet — run one to populate the dashboard"
	}
	writeJSON(w, resp)
}

// handleScan starts an audit in the background. The UI polls /api/state.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	deep := r.URL.Query().Get("mode") != "quick"

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeJSON(w, map[string]any{"started": false, "reason": "a scan is already running"})
		return
	}
	s.running = true
	s.lastErr = ""
	s.progress = "gathering container inventory"
	s.mu.Unlock()

	go func() {
		// Detached from the request: a deep scan outlives the HTTP call.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		opts := s.opts
		opts.Deep = deep
		sc, err := audit.Run(ctx, s.store, opts)
		s.mu.Lock()
		s.running = false
		s.progress = ""
		if err != nil {
			s.lastErr = err.Error()
			s.log.Printf("scan failed: %v", err)
		}
		s.mu.Unlock()
		if err == nil && len(s.sinks) > 0 {
			if a, ok := notify.Build(sc, false); ok {
				for _, e := range notify.Dispatch(ctx, a, s.sinks...) {
					s.log.Printf("notify: %v", e)
				}
			}
		}
	}()
	writeJSON(w, map[string]any{"started": true, "mode": map[bool]string{true: "full", false: "quick"}[deep]})
}

type fixRequest struct {
	ID string `json:"id"`
}

// handleFix runs the prepared command for one finding. Two guards: the server
// must be started with fixes enabled, and the finding itself must be marked
// applicable. Arbitrary commands are never accepted from the client — only the
// ID of a finding the scan produced.
func (s *Server) handleFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.fixes {
		http.Error(w, "fixes are disabled; start the server with --enable-fixes", http.StatusForbidden)
		return
	}
	var req fixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sc, err := s.store.Latest()
	if err != nil {
		http.Error(w, "no scan available", http.StatusConflict)
		return
	}
	var target *model.Finding
	for i := range sc.Findings {
		if sc.Findings[i].ID == req.ID {
			target = &sc.Findings[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "unknown finding", http.StatusNotFound)
		return
	}
	if !target.FixApply || target.FixCmd == "" {
		http.Error(w, "this finding has no automatic fix", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	s.log.Printf("applying fix for %s (%s): %s", target.ID, target.Rule, target.FixCmd)
	out, err := exec.CommandContext(ctx, "sh", "-c", target.FixCmd).CombinedOutput()
	resp := map[string]any{
		"id":      target.ID,
		"command": target.FixCmd,
		"output":  string(out),
		"ok":      err == nil,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("encode: %v", err), http.StatusInternalServerError)
	}
}
