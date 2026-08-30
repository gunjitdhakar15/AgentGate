package judge

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// Approver is the human-in-the-loop checkpoint required before a
// RouteNeedsApproval call proceeds. This satisfies the hackathon's ground
// rule that consequential actions get a qualified human reviewer before
// execution — the interface is deliberately small so a real deployment can
// swap the CLI prompt below for a Slack approval, a web dashboard button,
// or anything else, without touching the routing logic in router.go.
type Approver interface {
	// RequestApproval blocks until a human approves or denies the call, or
	// ctx is cancelled. err is non-nil only for a genuine failure of the
	// approval channel itself (not for a denial — a denial is
	// approved=false, err=nil).
	RequestApproval(ctx context.Context, tc ToolCallContext, v Verdict) (approved bool, err error)
}

// CLIApprover prompts on stdin/stdout. This is the reference
// implementation used by the demo and by default config — good enough to
// prove the checkpoint works end to end; not what a real multi-user
// deployment would ship.
type CLIApprover struct {
	in  *bufio.Reader
	out *os.File
}

func NewCLIApprover() *CLIApprover {
	return &CLIApprover{in: bufio.NewReader(os.Stdin), out: os.Stdout}
}

func (a *CLIApprover) RequestApproval(ctx context.Context, tc ToolCallContext, v Verdict) (bool, error) {
	fmt.Fprintf(a.out, "\n[AgentGate] Approval needed — risk_score=%.2f category=%s\n", v.RiskScore, v.Category)
	fmt.Fprintf(a.out, "  tool: %s\n  args: %v\n  reason: %s\n", tc.Tool, tc.Arguments, v.Rationale)
	fmt.Fprint(a.out, "  Allow this call? [y/N]: ")

	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := a.in.ReadString('\n')
		ch <- result{line, err}
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return false, fmt.Errorf("approver: read stdin: %w", r.err)
		}
		ans := strings.ToLower(strings.TrimSpace(r.line))
		return ans == "y" || ans == "yes", nil
	}
}

// AutoDenyApprover denies every call requiring approval without prompting.
// Useful for non-interactive contexts (CI, the eval harness) where there is
// no human to ask — RouteNeedsApproval should not silently become allow
// just because nobody's watching.
type AutoDenyApprover struct{}

func (AutoDenyApprover) RequestApproval(ctx context.Context, tc ToolCallContext, v Verdict) (bool, error) {
	return false, nil
}
