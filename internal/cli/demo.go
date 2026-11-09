package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/web"
)

// demoScenario is one canned tools/call in the self-generated demo traffic.
type demoScenario struct {
	tool      string
	args      map[string]any
	allowed   bool
	decision  string
	redactKey string
}

var demoScenarios = []demoScenario{
	{tool: "read_file", args: map[string]any{"path": "/home/user/.env", "api_key": "sk-demo-secret-0123456789abcdef"}, allowed: true, redactKey: "api_key"},
	{tool: "shell", args: map[string]any{"cmd": "ls -la"}, allowed: true},
	{tool: "shell", args: map[string]any{"cmd": "rm -rf /"}, allowed: false, decision: "destructive shell commands blocked"},
	{tool: "write_file", args: map[string]any{"path": "/tmp/evil.exe", "content": "malware"}, allowed: false, decision: "deny all tools by default"},
	{tool: "read_file", args: map[string]any{"path": "/etc/hosts"}, allowed: true},
	{tool: "http_get", args: map[string]any{"url": "https://api.example.com/v1/keys", "token": "bearer-demo-token-abcdefghij"}, allowed: true, redactKey: "token"},
	{tool: "shell", args: map[string]any{"cmd": "format C:"}, allowed: false, decision: "destructive shell commands blocked"},
	{tool: "write_file", args: map[string]any{"path": "/data/report.txt", "content": "monthly report"}, allowed: true},
	{tool: "read_file", args: map[string]any{"path": "/etc/passwd"}, allowed: false, decision: "sensitive path denied"},
	{tool: "shell", args: map[string]any{"cmd": "git status"}, allowed: true},
	{tool: "search_web", args: map[string]any{"query": "go best practices"}, allowed: true},
	{tool: "shell", args: map[string]any{"cmd": "curl http://192.168.1.1/admin"}, allowed: false, decision: "blocked by policy rule"},
}

// StartDemoTraffic streams synthetic MCP traffic through the firewall dashboard.
func StartDemoTraffic(ctx context.Context, dash *web.Dashboard) {
	var id atomic.Int64
	emit := func(e audit.Entry) {
		e.RequestID = fmt.Sprintf("demo-%d", id.Add(1))
		dash.Notify(e)
	}

	go func() {
		// Emit initial session event
		emit(audit.Entry{
			TS:       time.Now(),
			Kind:     "request",
			Method:   "initialize",
			Duration: 10 * time.Millisecond,
		})

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		idx := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sc := demoScenarios[idx%len(demoScenarios)]
				idx++

				redactedArgs := cloneArgs(sc.args)
				if sc.redactKey != "" {
					redactedArgs[sc.redactKey] = "***"
				}

				redJSON := mustJSON(redactedArgs)

				// 1. Request entry
				emit(audit.Entry{
					TS:       time.Now(),
					Kind:     "request",
					Method:   "tools/call",
					Tool:     sc.tool,
					Args:     redJSON,
					Duration: 2 * time.Millisecond,
				})

				// 2. Decision entry
				if !sc.allowed {
					emit(audit.Entry{
						TS:       time.Now(),
						Kind:     "blocked",
						Method:   "tools/call",
						Tool:     sc.tool,
						Args:     redJSON,
						Decision: sc.decision,
						Duration: 15 * time.Millisecond,
					})
				} else if sc.redactKey != "" {
					emit(audit.Entry{
						TS:       time.Now(),
						Kind:     "redacted",
						Method:   "tools/call",
						Tool:     sc.tool,
						Args:     redJSON,
						Decision: "arguments",
						Duration: 8 * time.Millisecond,
					})
					emit(audit.Entry{
						TS:       time.Now(),
						Kind:     "response",
						Method:   "tools/call",
						Tool:     sc.tool,
						Result:   demoResult(sc.tool, redactedArgs),
						Duration: 25 * time.Millisecond,
					})
				} else {
					emit(audit.Entry{
						TS:       time.Now(),
						Kind:     "response",
						Method:   "tools/call",
						Tool:     sc.tool,
						Result:   demoResult(sc.tool, redactedArgs),
						Duration: 22 * time.Millisecond,
					})
				}
			}
		}
	}()
}

func cloneArgs(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func demoResult(tool string, args map[string]any) json.RawMessage {
	argsJSON, _ := json.Marshal(args)
	out, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{
			"type": "text", "text": fmt.Sprintf("demo executed %s with %s", tool, argsJSON),
		}},
	})
	return out
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
