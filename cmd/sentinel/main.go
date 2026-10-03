// Command sentinel audits the Docker containers, host and network of a
// self-hosted machine and serves the results as a dashboard.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alminisl/security-bot/internal/audit"
	"github.com/alminisl/security-bot/internal/model"
	"github.com/alminisl/security-bot/internal/narrate"
	"github.com/alminisl/security-bot/internal/notify"
	"github.com/alminisl/security-bot/internal/store"
)

var version = "0.1.0-poc"

func main() {
	log.SetFlags(log.Ltime)
	lg := log.New(os.Stderr, "", log.Ltime)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "scan":
		os.Exit(cmdScan(lg, args))
	case "serve":
		os.Exit(cmdServe(lg, args))
	case "version", "--version", "-v":
		fmt.Println("sentinel", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sentinel — security auditor for a self-hosted Docker machine

usage:
  sentinel scan  [flags]   run an audit, print a summary, store the result
  sentinel serve [flags]   run the dashboard
  sentinel version

scan flags:
  --quick            skip registry and CVE checks (seconds instead of minutes)
  --json             print the full scan as JSON
  --no-llm           skip the written auditor's note
  --notify           send desktop/webhook alerts for new critical and high findings

serve flags:
  --addr HOST:PORT   listen address (default 127.0.0.1:7777)
  --enable-fixes     allow applying prepared fixes from the dashboard
  --scan-on-start    run an audit as soon as the server starts
  --sample-every D   traffic sampling interval, e.g. 60s (0 disables)

common flags:
  --state DIR        state directory (default ~/.local/state/sentinel)
  --model NAME       ollama model for the report (default qwen3:4b-instruct)
  --ollama URL       ollama endpoint (default http://127.0.0.1:11434)
  --webhook URL      POST alerts here (ntfy, Gotify, Home Assistant, …)
`)
}

type commonFlags struct {
	state   string
	model   string
	ollama  string
	webhook string
	noLLM   bool
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.state, "state", "", "state directory")
	fs.StringVar(&c.model, "model", envOr("SENTINEL_MODEL", "qwen3:4b-instruct"), "ollama model")
	fs.StringVar(&c.ollama, "ollama", envOr("OLLAMA_HOST", "http://127.0.0.1:11434"), "ollama endpoint")
	fs.StringVar(&c.webhook, "webhook", os.Getenv("SENTINEL_WEBHOOK"), "alert webhook URL")
	fs.BoolVar(&c.noLLM, "no-llm", false, "skip the written report")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		if key == "OLLAMA_HOST" && !strings.HasPrefix(v, "http") {
			return "http://" + v
		}
		return v
	}
	return def
}

// narrator returns the ollama client, which probes reachability on each report
// and errors quickly when ollama is absent. The audit then falls back to a
// factual summary. Deliberately not probed here: `serve` is long-lived and may
// start before ollama is up.
func (c *commonFlags) narrator(lg *log.Logger) audit.Narrator {
	if c.noLLM {
		return nil
	}
	return narrate.NewOllama(c.ollama, c.model)
}

func (c *commonFlags) sinks() []notify.Sink {
	sinks := []notify.Sink{notify.Desktop{}}
	if c.webhook != "" {
		sinks = append(sinks, notify.Webhook{URL: c.webhook})
	}
	return sinks
}

func cmdScan(lg *log.Logger, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var cf commonFlags
	cf.bind(fs)
	quick := fs.Bool("quick", false, "skip registry and CVE checks")
	asJSON := fs.Bool("json", false, "print the scan as JSON")
	doNotify := fs.Bool("notify", false, "send alerts for new critical/high findings")
	_ = fs.Parse(args)

	st, err := store.Open(cf.state)
	if err != nil {
		lg.Printf("state: %v", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sc, err := audit.Run(ctx, st, audit.Options{
		Deep:     !*quick,
		Timeout:  30 * time.Second,
		Narrator: cf.narrator(lg),
		Log:      lg,
	})
	if err != nil {
		lg.Printf("scan failed: %v", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sc)
	} else {
		printSummary(sc, st.Dir)
	}

	if *doNotify {
		if a, ok := notify.Build(sc, false); ok {
			for _, e := range notify.Dispatch(ctx, a, cf.sinks()...) {
				lg.Printf("notify: %v", e)
			}
		}
	}
	if sc.Counts["critical"] > 0 {
		return 2 // non-zero so a timer or CI step can react
	}
	return 0
}

func printSummary(sc *model.Scan, dir string) {
	fmt.Printf("\n  Sentinel audit %s — rating %d/100 (%.1fs)\n", sc.ID, sc.Score, float64(sc.DurMS)/1000)
	fmt.Printf("  %s\n\n", strings.Repeat("─", 64))
	fmt.Printf("  %s\n\n", wrap(sc.Report, 62, "  "))
	fmt.Printf("  critical %d   high %d   medium %d   low %d   info %d\n",
		sc.Counts["critical"], sc.Counts["high"], sc.Counts["medium"], sc.Counts["low"], sc.Counts["info"])
	fmt.Printf("  machine %d/100   network %d/100   %d projects\n\n", sc.Machine.Score, sc.Network.Score, len(sc.Projects))

	if alerts := sc.Alerts; len(alerts) > 0 {
		fmt.Println("  React now:")
		for i, f := range alerts {
			if i >= 8 {
				fmt.Printf("    … and %d more\n", len(alerts)-i)
				break
			}
			flag := " "
			if f.New {
				flag = "*"
			}
			fmt.Printf("   %s [%-8s] %s — %s\n", flag, f.Severity, f.Title, f.Target)
		}
		fmt.Println()
	}
	if len(sc.Suggestions) > 0 {
		fmt.Println("  Suggestions:")
		for i, s := range sc.Suggestions {
			if i >= 5 {
				break
			}
			fmt.Printf("    %d. %s\n", i+1, s.Title)
		}
		fmt.Println()
	}
	fmt.Println("  Weakest projects:")
	for i, p := range sc.Projects {
		if i >= 5 || p.Score == 100 {
			break
		}
		fmt.Printf("    %-28s %3d/100\n", p.Key, p.Score)
	}
	fmt.Printf("\n  stored in %s — run `sentinel serve` for the dashboard\n\n", dir)
}

// wrap breaks text at a width for terminal output.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n"+indent)
}

func cmdServe(lg *log.Logger, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var cf commonFlags
	cf.bind(fs)
	addr := fs.String("addr", "127.0.0.1:7777", "listen address")
	enableFixes := fs.Bool("enable-fixes", false, "allow applying fixes from the dashboard")
	scanOnStart := fs.Bool("scan-on-start", false, "run an audit at startup")
	sampleEvery := fs.Duration("sample-every", time.Minute, "traffic sampling interval (0 disables)")
	_ = fs.Parse(args)

	st, err := store.Open(cf.state)
	if err != nil {
		lg.Printf("state: %v", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := audit.Options{Deep: true, Timeout: 30 * time.Second, Narrator: cf.narrator(lg), Log: lg}
	srv := newServer(st, opts, lg, *enableFixes, cf.sinks())

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	srv.StartSampler(ctx, *sampleEvery)

	if *scanOnStart {
		go func() {
			if _, err := audit.Run(ctx, st, opts); err != nil {
				lg.Printf("startup scan: %v", err)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()

	lg.Printf("dashboard on http://%s (fixes %s)", *addr,
		map[bool]string{true: "enabled", false: "disabled"}[*enableFixes])
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		lg.Printf("serve: %v", err)
		return 1
	}
	return 0
}
