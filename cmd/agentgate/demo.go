package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
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

// StartDemoTraffic feeds realistic audit entries into the dashboard so the
// hosted demo shows live firewall activity without a real agent attached.
func StartDemoTraffic(ctx context.Context, dash *web.Dashboard) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	var id atomic.Int64
	emit := func(eventID int64, e audit.Entry) {
		e.RequestID = fmt.Sprintf("demo-%d", eventID)
		dash.Notify(e)
	}

	go func() {
		settle := time.NewTimer(900 * time.Millisecond)
		select {
		case <-ctx.Done():
			return
		case <-settle.C:
		}
		emit(id.Add(1), audit.Entry{TS: time.Now(), Kind: "request", Method: "initialize", Duration: 12 * time.Millisecond})

		ticker := time.NewTicker(1600 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := demoScenarios[rnd.Intn(len(demoScenarios))]
				now := time.Now()
				emit(id.Add(1), audit.Entry{
					TS: now, Kind: "request", Method: "tools/call",
					Duration: time.Duration(rnd.Intn(50)+5) * time.Millisecond,
				})
				time.Sleep(time.Duration(rnd.Intn(120)+40) * time.Millisecond)

				args := cloneArgs(s.args)
				if s.allowed {
					if s.redactKey != "" && args[s.redactKey] != nil {
						args[s.redactKey] = "***"
						emit(id.Add(1), audit.Entry{
							TS: time.Now(), Kind: "redacted", Method: "tools/call",
							Tool: s.tool, Decision: "arguments", Args: mustJSON(args),
						})
					}
					emit(id.Add(1), audit.Entry{
						TS: time.Now(), Kind: "response", Method: "tools/call",
						Tool: s.tool, Result: demoResult(s.tool, args),
					})
				} else {
					emit(id.Add(1), audit.Entry{
						TS: time.Now(), Kind: "blocked", Method: "tools/call",
						Tool: s.tool, Decision: s.decision, Args: mustJSON(args),
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
