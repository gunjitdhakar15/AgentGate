package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
)

func entry(kind, tool string) audit.Entry {
	return audit.Entry{TS: time.Now(), Kind: kind, Tool: tool}
}

func TestDashboardCounters(t *testing.T) {
	d := New()
	d.handleEntry(entry("request", ""))
	d.handleEntry(entry("request", ""))
	d.handleEntry(entry("response", "read_file"))
	d.handleEntry(entry("blocked", "shell"))
	d.handleEntry(entry("blocked", "shell"))
	d.handleEntry(entry("redacted", "shell"))
	d.handleEntry(entry("protocol", ""))

	s := d.snapshotObject()
	if s.Counters["total"] != 2 {
		t.Errorf("total = %d, want 2", s.Counters["total"])
	}
	if s.Counters["allowed"] != 1 {
		t.Errorf("allowed = %d, want 1", s.Counters["allowed"])
	}
	if s.Counters["blocked"] != 2 {
		t.Errorf("blocked = %d, want 2", s.Counters["blocked"])
	}
	if s.Counters["redacted"] != 1 {
		t.Errorf("redacted = %d, want 1", s.Counters["redacted"])
	}
	if s.Counters["protocolError"] != 1 {
		t.Errorf("protocolError = %d, want 1", s.Counters["protocolError"])
	}
	if len(s.Recent) != 7 {
		t.Errorf("recent = %d, want 7", len(s.Recent))
	}
	if s.Tools["shell"].Blocked != 2 {
		t.Errorf("shell blocked = %d, want 2", s.Tools["shell"].Blocked)
	}
	if s.Tools["read_file"].Allowed != 1 {
		t.Errorf("read_file allowed = %d, want 1", s.Tools["read_file"].Allowed)
	}
	if s.Tools["shell"].Redacted != 1 {
		t.Errorf("shell redacted = %d, want 1", s.Tools["shell"].Redacted)
	}
}

func TestDashboardBroadcast(t *testing.T) {
	d := New()
	ch, done := d.Subscribe()
	defer done()

	e := entry("blocked", "shell")
	d.handleEntry(e)

	select {
	case ev := <-ch:
		if ev.Type != "entry" {
			t.Errorf("event type = %q, want entry", ev.Type)
		}
		got := ev.Data.(audit.Entry)
		if got.Tool != "shell" {
			t.Errorf("event tool = %q, want shell", got.Tool)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received on subscriber channel")
	}
}

func TestDashboardSlowSubscriberDropped(t *testing.T) {
	d := New()
	// Never drain the channel; the broadcast must not block.
	_, done := d.Subscribe()
	defer done()
	for i := 0; i < 300; i++ {
		d.handleEntry(entry("request", ""))
	}
	s := d.snapshotObject()
	if s.Counters["total"] != 300 {
		t.Errorf("total = %d, want 300", s.Counters["total"])
	}
}

func TestDashboardConcurrentSubscribeAndBroadcast(t *testing.T) {
	d := New()
	stop := make(chan struct{})

	// Spin up subscriber goroutines that rapidly subscribe and unsubscribe
	for i := 0; i < 5; i++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					ch, done := d.Subscribe()
					select {
					case <-ch:
					case <-time.After(time.Millisecond):
					}
					done()
				}
			}
		}()
	}

	// Spin up broadcaster sending entries concurrently
	for i := 0; i < 200; i++ {
		d.Notify(entry("request", "shell"))
		time.Sleep(100 * time.Microsecond)
	}
	close(stop)
}

func TestEvaluateEndpointBlocksSemanticGapWithCmdKey(t *testing.T) {
	d := New()
	handler := d.Handler()

	// Scenario sem-1 as sent by dashboard.html: tool "shell", arguments {"cmd": "find / -delete"}
	body, _ := json.Marshal(map[string]any{
		"tool": "shell",
		"arguments": map[string]any{
			"cmd": "find / -delete",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp EvalResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode eval response: %v", err)
	}

	if resp.FinalVerdict != "BLOCK" {
		t.Fatalf("expected semantic gap attack 'find / -delete' with 'cmd' key to be BLOCK, got %q", resp.FinalVerdict)
	}
	if resp.RiskScore < 0.8 {
		t.Fatalf("expected high risk score >= 0.8, got %.2f", resp.RiskScore)
	}
}

func TestEvaluateEndpointTriggersHITLReview(t *testing.T) {
	d := New()
	handler := d.Handler()

	// Scenario hitl-1: tool "shell", arguments {"cmd": "crontab -e"}
	body, _ := json.Marshal(map[string]any{
		"tool": "shell",
		"arguments": map[string]any{
			"cmd": "crontab -e",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp EvalResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode eval response: %v", err)
	}

	if resp.FinalVerdict != "REVIEW" {
		t.Fatalf("expected 'crontab -e' to require REVIEW (needs_approval), got %q", resp.FinalVerdict)
	}
	if resp.RiskScore < 0.4 || resp.RiskScore >= 0.8 {
		t.Fatalf("expected gray zone risk score in [0.4, 0.8), got %.2f", resp.RiskScore)
	}
}

func TestHITLEndpoints(t *testing.T) {
	d := New()
	approver := judge.NewWebApprover(func(p judge.PendingApproval) {
		d.Broadcast("approval_required", p)
	})
	d.Approver = approver
	handler := d.Handler()

	// Start request in background
	approvedCh := make(chan bool)
	go func() {
		app, _ := approver.RequestApproval(context.Background(), judge.ToolCallContext{
			Tool:      "shell",
			Arguments: map[string]any{"cmd": "crontab -e"},
		}, judge.Verdict{RiskScore: 0.65, Category: judge.CategoryPersistence})
		approvedCh <- app
	}()

	// Wait until pending
	for len(approver.Pending()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	pendingID := approver.Pending()[0].ID

	// Check /api/hitl/pending
	pReq := httptest.NewRequest(http.MethodGet, "/api/hitl/pending", nil)
	pRec := httptest.NewRecorder()
	handler.ServeHTTP(pRec, pReq)
	if pRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", pRec.Code)
	}
	if !strings.Contains(pRec.Body.String(), pendingID) {
		t.Errorf("expected pending list to contain %s, got %s", pendingID, pRec.Body.String())
	}

	// Call /api/hitl/approve
	aBody := fmt.Sprintf(`{"id":"%s"}`, pendingID)
	aReq := httptest.NewRequest(http.MethodPost, "/api/hitl/approve", strings.NewReader(aBody))
	aRec := httptest.NewRecorder()
	handler.ServeHTTP(aRec, aReq)
	if aRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on approve, got %d", aRec.Code)
	}

	select {
	case result := <-approvedCh:
		if !result {
			t.Errorf("expected approver to unblock with true")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for approval unblock")
	}
}
