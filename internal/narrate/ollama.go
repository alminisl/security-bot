// Package narrate turns a finished scan into the auditor's written note using
// a local ollama model, so the container inventory never leaves the machine.
package narrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

type Ollama struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

func NewOllama(baseURL, modelName string) *Ollama {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:11434"
	}
	if modelName == "" {
		modelName = "qwen3:4b-instruct"
	}
	return &Ollama{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Model:   modelName,
		Client:  &http.Client{Timeout: 3 * time.Minute},
	}
}

// Available reports whether ollama is reachable, so the caller can fall back
// quietly instead of waiting on a timeout.
func (o *Ollama) Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type genRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	System  string         `json:"system"`
	Stream  bool           `json:"stream"`
	Think   bool           `json:"think"`
	Options map[string]any `json:"options,omitempty"`
}

type genResponse struct {
	Response string `json:"response"`
	Error    string `json:"error"`
}

const systemPrompt = `You are a security auditor writing the summary note at the top of a homelab audit report.
Write 3 to 5 short sentences of plain prose. No markdown, no bullet points, no headings, no preamble.
Lead with the single most urgent issue and say plainly why it matters.
Be specific: name the containers, projects and ports from the data.
Do not invent findings, CVE numbers or counts that are not in the data. Do not give a score.
Write calmly and directly, like a colleague who has just finished reading the report.`

// thinkBlock strips reasoning traces that thinking models emit even when asked
// not to.
var thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>|(?s)<thinking>.*?</thinking>`)

func (o *Ollama) Report(ctx context.Context, sc *model.Scan) (string, error) {
	// Check reachability first so an absent ollama fails in seconds rather
	// than holding the scan open for the full client timeout.
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if !o.Available(probe) {
		return "", fmt.Errorf("ollama not reachable at %s", o.BaseURL)
	}

	body, err := json.Marshal(genRequest{
		Model:  o.Model,
		System: systemPrompt,
		Prompt: buildPrompt(sc),
		Stream: false,
		Think:  false,
		Options: map[string]any{
			"temperature": 0.3,
			"num_predict": 300,
		},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned %s", resp.Status)
	}
	var gr genResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}
	if gr.Error != "" {
		return "", fmt.Errorf("ollama: %s", gr.Error)
	}
	out := strings.TrimSpace(thinkBlock.ReplaceAllString(gr.Response, ""))
	// Models sometimes still open a think block without closing it.
	if i := strings.Index(out, "</think>"); i >= 0 {
		out = strings.TrimSpace(out[i+len("</think>"):])
	}
	out = strings.TrimPrefix(out, "<think>")
	if out == "" {
		return "", fmt.Errorf("empty response from %s", o.Model)
	}
	return out, nil
}

// buildPrompt gives the model the facts and nothing else: counts, the worst
// findings, and the weakest scopes.
func buildPrompt(sc *model.Scan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Audit of a self-hosted Linux server running %d Docker containers in %d compose projects.\n\n",
		len(sc.Containers), len(sc.Projects))
	fmt.Fprintf(&b, "Finding counts: %d critical, %d high, %d medium, %d low.\n",
		sc.Counts["critical"], sc.Counts["high"], sc.Counts["medium"], sc.Counts["low"])
	if sc.NewCount > 0 {
		fmt.Fprintf(&b, "%d findings are new since the last scan.\n", sc.NewCount)
	}
	if sc.Resolved > 0 {
		fmt.Fprintf(&b, "%d findings were resolved since the last scan.\n", sc.Resolved)
	}

	b.WriteString("\nMost serious findings:\n")
	limit := 12
	for i, f := range sc.Findings {
		if i >= limit {
			break
		}
		fmt.Fprintf(&b, "- [%s] %s — %s (%s)\n", strings.ToUpper(string(f.Severity)), f.Title, f.Target, f.ScopeKey)
	}

	b.WriteString("\nWeakest areas:\n")
	for i, p := range sc.Projects {
		if i >= 4 || p.Score == 100 {
			break
		}
		fmt.Fprintf(&b, "- project %s: %d/100\n", p.Key, p.Score)
	}
	fmt.Fprintf(&b, "- host machine: %d/100\n- network: %d/100\n", sc.Machine.Score, sc.Network.Score)

	for _, a := range sc.Agents {
		if a.Status == "unavailable" {
			fmt.Fprintf(&b, "\nNote: the %s could not run (%s), so that coverage is missing.\n", a.Title, a.Message)
		}
	}
	b.WriteString("\nWrite the auditor's summary note now.")
	return b.String()
}
