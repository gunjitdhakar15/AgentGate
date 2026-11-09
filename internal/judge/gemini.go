package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultGeminiModel = "gemini-2.5-flash"

// GeminiJudge evaluates tool calls using Google's Gemini API via structured JSON.
type GeminiJudge struct {
	APIKey string
	Model  string
	HTTP   *http.Client
}

// NewGeminiJudge creates a new Google Gemini judge instance.
func NewGeminiJudge(apiKey, model string) *GeminiJudge {
	if model == "" {
		model = defaultGeminiModel
	}
	return &GeminiJudge{
		APIKey: apiKey,
		Model:  model,
		HTTP:   &http.Client{Timeout: 15 * time.Second},
	}
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
	GenerationConfig  map[string]any  `json:"generationConfig"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (j *GeminiJudge) Assess(ctx context.Context, tc ToolCallContext) (Verdict, error) {
	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		url.PathEscape(j.Model), url.QueryEscape(j.APIKey))

	reqBody := geminiRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: SystemRubric}},
		},
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: FormatUserPrompt(tc)}}},
		},
		GenerationConfig: map[string]any{
			"response_mime_type": "application/json",
			"temperature":        0.0,
		},
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return Verdict{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(raw))
	if err != nil {
		return Verdict{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := j.HTTP.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Verdict{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("gemini error status %d: %s", resp.StatusCode, string(body))
	}

	var res geminiResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return Verdict{}, fmt.Errorf("parse gemini response: %w", err)
	}
	if len(res.Candidates) == 0 || len(res.Candidates[0].Content.Parts) == 0 {
		return Verdict{}, fmt.Errorf("gemini returned no candidate parts")
	}

	var out struct {
		RiskScore float64  `json:"risk_score"`
		Category  Category `json:"category"`
		Rationale string   `json:"rationale"`
	}
	content := strings.TrimSpace(res.Candidates[0].Content.Parts[0].Text)
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
