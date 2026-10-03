// Package notify delivers alerts about a finished scan. Only the local desktop
// and generic webhook sinks exist today; the interface is here so email, ntfy
// or Gotify can be added without touching the audit code.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// Sink is one delivery channel.
type Sink interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Alert is the payload: a short title, the body, and the findings behind it.
type Alert struct {
	Title    string          `json:"title"`
	Body     string          `json:"body"`
	Score    int             `json:"score"`
	Critical int             `json:"critical"`
	High     int             `json:"high"`
	Findings []model.Finding `json:"findings"`
}

// Build returns an alert for a scan, and false when nothing warrants one.
// Only new critical and high findings notify: a daily repeat of a known issue
// trains you to ignore the channel.
func Build(sc *model.Scan, includeExisting bool) (Alert, bool) {
	var fs []model.Finding
	for _, f := range sc.Alerts {
		if includeExisting || f.New {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return Alert{}, false
	}
	crit, high := 0, 0
	for _, f := range fs {
		if f.Severity == model.SevCritical {
			crit++
		} else {
			high++
		}
	}
	title := fmt.Sprintf("Security audit: %d critical, %d high", crit, high)
	var lines []string
	for i, f := range fs {
		if i >= 5 {
			lines = append(lines, fmt.Sprintf("…and %d more", len(fs)-i))
			break
		}
		lines = append(lines, fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(f.Severity)), f.Title, f.Target))
	}
	return Alert{
		Title:    title,
		Body:     strings.Join(lines, "\n"),
		Score:    sc.Score,
		Critical: crit,
		High:     high,
		Findings: fs,
	}, true
}

// Desktop uses notify-send, which only works when a session bus is present.
type Desktop struct{}

func (Desktop) Name() string { return "desktop" }

func (Desktop) Send(ctx context.Context, a Alert) error {
	if _, err := exec.LookPath("notify-send"); err != nil {
		return fmt.Errorf("notify-send not available")
	}
	urgency := "normal"
	if a.Critical > 0 {
		urgency = "critical"
	}
	return exec.CommandContext(ctx, "notify-send", "-u", urgency, "-a", "security-bot", a.Title, a.Body).Run()
}

// Webhook posts the alert as JSON, which covers ntfy, Gotify, Slack-style
// endpoints and Home Assistant with no extra code.
type Webhook struct {
	URL string
}

func (Webhook) Name() string { return "webhook" }

func (w Webhook) Send(ctx context.Context, a Alert) error {
	if w.URL == "" {
		return fmt.Errorf("no webhook URL configured")
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Title", a.Title)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// Dispatch sends the alert to every sink, collecting errors rather than
// stopping at the first failure.
func Dispatch(ctx context.Context, a Alert, sinks ...Sink) []error {
	var errs []error
	for _, s := range sinks {
		if err := s.Send(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errs
}
