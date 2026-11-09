package judge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIJudge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{
				"message": {
					"content": "{\"risk_score\": 0.95, \"category\": \"destructive\", \"rationale\": \"Recursive deletion of root.\"}"
				}
			}]
		}`))
	}))
	defer srv.Close()

	j := NewOpenAIJudge("test-key", "gpt-4o-mini", srv.URL)
	v, err := j.Assess(context.Background(), ToolCallContext{
		Tool:      "shell",
		Arguments: map[string]any{"cmd": "find / -delete"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.RiskScore != 0.95 {
		t.Errorf("expected risk score 0.95, got %f", v.RiskScore)
	}
	if v.Category != CategoryDestructive {
		t.Errorf("expected category destructive, got %s", v.Category)
	}
}

func TestGeminiJudge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {
					"parts": [{
						"text": "{\"risk_score\": 0.1, \"category\": \"safe\", \"rationale\": \"Safe read-only operation.\"}"
					}]
				}
			}]
		}`))
	}))
	defer srv.Close()

	j := NewGeminiJudge("test-key", "gemini-2.5-flash")
	j.HTTP = srv.Client()
	// Test Assess against custom test server by modifying internal URL or checking parse
	// Since Gemini URL is hardcoded to Google's host, we can verify error handling or constructor
	if j.Model != "gemini-2.5-flash" || j.APIKey != "test-key" {
		t.Fatalf("unexpected fields: %+v", j)
	}
}

func TestOllamaJudge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"response": "{\"risk_score\": 0.65, \"category\": \"persistence\", \"rationale\": \"Crontab edit requires approval.\"}"
		}`))
	}))
	defer srv.Close()

	j := NewOllamaJudge(srv.URL, "llama3.2")
	v, err := j.Assess(context.Background(), ToolCallContext{
		Tool:      "shell",
		Arguments: map[string]any{"cmd": "crontab -e"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.RiskScore != 0.65 {
		t.Errorf("expected risk score 0.65, got %f", v.RiskScore)
	}
	if v.Category != CategoryPersistence {
		t.Errorf("expected category persistence, got %s", v.Category)
	}
}
