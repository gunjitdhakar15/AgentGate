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
	defaultOpenAIModel   = "gpt-4o-mini"
	defaultOpenAIBaseURL = "https://api.openai.com/v1/chat/completions"
)

// OpenAIJudge evaluates tool calls using OpenAI or any OpenAI-compatible API
// (Groq, Together, DeepSeek, vLLM, LocalAI) using JSON schema response formatting.
type OpenAIJudge struct {
	APIKey  string
	Model   string
	BaseURL string
	HTTP    *http.Client
}

// NewOpenAIJudge creates a new OpenAI judge instance.
func NewOpenAIJudge(apiKey, model, baseURL string) *OpenAIJudge {
	if model == "" {
		model = defaultOpenAIModel
	}
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	} else if !strings.HasSuffix(baseURL, "/chat/completions") {
		baseURL = strings.TrimRight(baseURL, "/") + "/chat/completions"
	}

	return &OpenAIJudge{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model          string          `json:"model"`
	Messages       []openAIMessage `json:"messages"`
	ResponseFormat map[string]any  `json:"response_format"`
	Temperature    float64         `json:"temperature"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (j *OpenAIJudge) Assess(ctx context.Context, tc ToolCallContext) (Verdict, error) {
	reqBody := openAIRequest{
		Model: j.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: SystemRubric},
			{Role: "user", Content: FormatUserPrompt(tc)},
		},
		ResponseFormat: map[string]any{"type": "json_object"},
		Temperature:    0.0,
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return Verdict{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL, bytes.NewReader(raw))
	if err != nil {
		return Verdict{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+j.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := j.HTTP.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Verdict{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("openai error status %d: %s", resp.StatusCode, string(body))
	}

	var res openAIResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return Verdict{}, fmt.Errorf("parse openai response: %w", err)
	}
	if len(res.Choices) == 0 {
		return Verdict{}, fmt.Errorf("openai returned no choices")
	}

	var out struct {
		RiskScore float64  `json:"risk_score"`
		Category  Category `json:"category"`
		Rationale string   `json:"rationale"`
	}
	content := strings.TrimSpace(res.Choices[0].Message.Content)
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
