package judge

import (
	"context"
	"testing"
	"time"
)

func TestWebApprover_Approve(t *testing.T) {
	var notified PendingApproval
	approver := NewWebApprover(func(p PendingApproval) {
		notified = p
	})

	go func() {
		for approver.Pending() == nil || len(approver.Pending()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		list := approver.Pending()
		approver.Resolve(list[0].ID, true)
	}()

	approved, err := approver.RequestApproval(context.Background(), ToolCallContext{
		Tool:      "shell",
		Arguments: map[string]any{"cmd": "crontab -e"},
	}, Verdict{RiskScore: 0.65, Category: CategoryPersistence, Rationale: "Operator review needed"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Fatalf("expected approved=true")
	}
	if notified.Tool != "shell" {
		t.Errorf("expected notified tool shell, got %s", notified.Tool)
	}
}

func TestWebApprover_Deny(t *testing.T) {
	approver := NewWebApprover(nil)

	go func() {
		for len(approver.Pending()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		approver.Resolve(approver.Pending()[0].ID, false)
	}()

	approved, err := approver.RequestApproval(context.Background(), ToolCallContext{
		Tool:      "shell",
		Arguments: map[string]any{"cmd": "chmod 777 /etc"},
	}, Verdict{RiskScore: 0.7, Category: CategoryPrivilegeEscalation})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approved {
		t.Fatalf("expected approved=false")
	}
}
