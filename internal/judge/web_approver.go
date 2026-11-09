package judge

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PendingApproval represents an MCP tool call suspended in the [0.4, 0.8) gray zone awaiting human operator review.
type PendingApproval struct {
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Verdict   Verdict        `json:"verdict"`
	Timestamp time.Time      `json:"timestamp"`
	reply     chan bool
}

// WebApprover is an Approver implementation that exposes pending actions to the web dashboard.
type WebApprover struct {
	mu      sync.RWMutex
	pending map[string]*PendingApproval
	onReq   func(p PendingApproval)
	timeout time.Duration
}

// NewWebApprover constructs an approver that notifies the web dashboard via onReq callback.
func NewWebApprover(onReq func(p PendingApproval)) *WebApprover {
	return &WebApprover{
		pending: make(map[string]*PendingApproval),
		onReq:   onReq,
		timeout: 60 * time.Second,
	}
}

// RequestApproval blocks until an operator approves or denies via the web dashboard, or until timeout.
func (a *WebApprover) RequestApproval(ctx context.Context, tc ToolCallContext, v Verdict) (bool, error) {
	id := fmt.Sprintf("hitl-%d", time.Now().UnixNano()%100000)
	ch := make(chan bool, 1)

	p := &PendingApproval{
		ID:        id,
		Tool:      tc.Tool,
		Arguments: tc.Arguments,
		Verdict:   v,
		Timestamp: time.Now(),
		reply:     ch,
	}

	a.mu.Lock()
	a.pending[id] = p
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()

	if a.onReq != nil {
		a.onReq(*p)
	}

	timer := time.NewTimer(a.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		// Safe default deny on timeout
		return false, nil
	case approved := <-ch:
		return approved, nil
	}
}

// Resolve unblocks a pending approval with either allow (true) or block (false).
func (a *WebApprover) Resolve(id string, approved bool) bool {
	a.mu.Lock()
	p, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	a.mu.Unlock()

	if !ok {
		return false
	}

	select {
	case p.reply <- approved:
		return true
	default:
		return false
	}
}

// Pending returns a snapshot of active pending approvals.
func (a *WebApprover) Pending() []PendingApproval {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]PendingApproval, 0, len(a.pending))
	for _, p := range a.pending {
		out = append(out, PendingApproval{
			ID:        p.ID,
			Tool:      p.Tool,
			Arguments: p.Arguments,
			Verdict:   p.Verdict,
			Timestamp: p.Timestamp,
		})
	}
	return out
}
