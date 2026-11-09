package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultOllamaModel = "llama3.2"
	defaultOllamaHost  = "http://localhost:11434"
)

// OllamaJudge evaluates tool calls completely offline and locally using Ollama.
type OllamaJudge struct {
	BaseURL string
	Model   string
	HTTP    *http.Client
}

// NewOllamaJudge creates a new Ollama judge instance.
func NewOllamaJudge(baseURL, model string) *OllamaJudge {
	if model == "" {
		model = defaultOllamaModel
	}
	if baseURL == "" {
		baseURL = defaultOllamaHost
	}
	baseURL = strings.TrimRight(baseURL, "/") + "/api/generate"

	return &OllamaJudge{
		BaseURL: baseURL,
		Model:   model,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

type ollamaRequest struct {
	Model   string         `json:"model"`
	System  string         `json:"system"`
	Prompt  string         `json:"prompt"`
	Format  string         `json:"format"`
	Stream  bool           `json:"stream"`
	Options map[string]any `json:"options"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

func (j *OllamaJudge) Assess(ctx context.Context, tc ToolCallContext) (Verdict, error) {
	reqBody := ollamaRequest{
		Model:   j.Model,
		System:  SystemRubric,
		Prompt:  FormatUserPrompt(tc),
		Format:  "json",
		Stream:  false,
		Options: map[string]any{"temperature": 0.0},
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return Verdict{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL, bytes.NewReader(raw))
	if err != nil {
		return Verdict{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := j.HTTP.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("ollama request (is Ollama running at %s?): %w", j.BaseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Verdict{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("ollama error status %d: %s", resp.StatusCode, string(body))
	}

	var res ollamaResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return Verdict{}, fmt.Errorf("parse ollama response: %w", err)
	}
	if res.Error != "" {
		return Verdict{}, fmt.Errorf("ollama returned error: %s", res.Error)
	}

	var out struct {
		RiskScore float64  `json:"risk_score"`
		Category  Category `json:"category"`
		Rationale string   `json:"rationale"`
	}
	content := strings.TrimSpace(res.Response)
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return Verdict{}, fmt.Errorf("parse verdict json %q: %w", content, err)
	}

	if out.RiskScore < 0 {
		out.RiskScore = 0
	} else if out.RiskScore > 1.0 {
		out.RiskScore = 1.0
	}

	return Verdict{
		RiskScore: out.RiskScore,
		Category:  out.Category,
		Rationale: out.Rationale,
	}, nil
}
