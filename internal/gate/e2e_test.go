package gate

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
)

// testGate builds a gate wired to a fake tool server through deterministic
// synchronous pipes. It returns the gate and the two agent-side ends:
// the writer pushes request lines into the gate, the reader yields replies.
func testGate(t *testing.T, cp *compiledPolicy) (*Gate, *io.PipeWriter, *io.PipeReader, *audit.Store) {
	t.Helper()

	// Agent -> gate direction.
	reqR, reqW := io.Pipe()
	// Gate -> agent direction.
	respR, respW := io.Pipe()
	// Gate -> tool server direction.
	callR, callW := io.Pipe()
	// Tool server -> gate direction.
	retR, retW := io.Pipe()

	agent := mcp.NewStream(reqR, respW)
	server := mcp.NewStream(retR, callW)
	fake := mcp.NewStream(callR, retW)

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	g := New(cp, store, log.New(io.Discard, "", 0))
	go func() { _ = g.Serve(context.Background(), agent, server) }()
	go fakeToolServer(t, fake)

	return g, reqW, respR, store
}

// fakeToolServer is an in-process MCP tool server speaking stdio framing.
// It answers initialize, tools/list and tools/call, echoing arguments back so
// tests can assert what actually reached the server.
func fakeToolServer(t *testing.T, s *mcp.Stream) {
	t.Helper()
	for {
		data, err := s.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Errorf("fake server read: %v", err)
			return
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(data, &probe)
		switch probe.Method {
		case "initialize":
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{"protocolVersion":"2025-06-18"}`)})
		case "tools/list":
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{"tools":[{"name":"shell"},{"name":"read_file"}]}`)})
		case "tools/call":
			var call struct {
				Params struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"params"`
			}
			_ = json.Unmarshal(data, &call)
			out, _ := json.Marshal(map[string]any{
				"content": []map[string]any{{
					"type": "text", "text": "ran " + call.Params.Name + " with key=" + anyStr(call.Params.Arguments, "api_key"),
				}},
			})
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: out})
		default:
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{}`)})
		}
	}
}

func anyStr(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return "<missing>"
}

// e2eRun drives a single request through the gate from the agent side and
// returns the raw response line.
func e2eRun(t *testing.T, w *io.PipeWriter, r *io.PipeReader, method string, payload any) []byte {
	t.Helper()
	req := mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method}
	if payload != nil {
		req.Params, _ = json.Marshal(payload)
	}
	line, _ := json.Marshal(req)
	if _, err := w.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	// Synchronous pipe: the reply arrives on the same goroutine. Read with a
	// deadline-equivalent timeout.
	buf := make([]byte, 64*1024)
	ch := make(chan []byte, 1)
	go func() {
		n, err := r.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- append([]byte(nil), buf[:n]...)
	}()
	select {
	case data := <-ch:
		if data == nil {
			t.Fatal("gate closed the stream")
		}
		return data
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for gate reply")
		return nil
	}
}

func TestE2EBlockedAndRedacted(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "*", Deny: true},
		{ApplyTo: "read_file", Allow: true},
	}, []RedactRule{
		{Keys: []string{"api_key"}, Pattern: ".*", Replacement: "***"},
	}, nil)

	_, w, r, store := testGate(t, cp)

	// Blocked call: shell is denied.
	data := e2eRun(t, w, r, "tools/call", map[string]any{
		"name":      "shell",
		"arguments": map[string]any{"cmd": "ls"},
	})
	var resp mcp.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("blocked response must be valid JSON: %v (got %q)", err, data)
	}
	if resp.Error != nil {
		t.Fatalf("blocked response should be a result with isError, got RPC error: %+v", resp.Error)
	}
	if !json.Valid(resp.Result) {
		t.Fatal("blocked result must be JSON")
	}

	// Allowed call reaches the server with redacted arguments and a redacted
	// response comes back.
	data = e2eRun(t, w, r, "tools/call", map[string]any{
		"name":      "read_file",
		"arguments": map[string]any{"path": "/etc/hosts", "api_key": "sk-hunter2"},
	})
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatal(err)
	}
	out := string(resp.Result)
	if contains(out, "sk-hunter2") {
		t.Fatalf("secret leaked to agent in response: %s", out)
	}

	// Audit log must carry the blocked record with no secrets.
	entries, err := audit.Replay(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	var blocked []audit.Entry
	for _, e := range entries {
		if e.Kind == "blocked" {
			blocked = append(blocked, e)
		}
	}
	if len(blocked) != 1 {
		t.Fatalf("want exactly 1 blocked entry, got %d", len(blocked))
	}
	if string(blocked[0].Args) == "" {
		t.Fatal("blocked entry should record the redacted args")
	}
}

func TestE2ERateLimitBlocks(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "*", Allow: true},
	}, nil, []RateLimit{{ApplyTo: "shell", Burst: 2, Window: time.Minute}})

	_, w, r, _ := testGate(t, cp)
	for i := 1; i <= 2; i++ {
		data := e2eRun(t, w, r, "tools/call", map[string]any{
			"name": "shell", "arguments": map[string]any{"cmd": "echo hi"},
		})
		var resp mcp.Response
		_ = json.Unmarshal(data, &resp)
		if string(resp.Result) == "" || contains(string(resp.Result), "AgentGate blocked") {
			t.Fatalf("call %d should pass rate limit", i)
		}
	}
	data := e2eRun(t, w, r, "tools/call", map[string]any{
		"name": "shell", "arguments": map[string]any{"cmd": "echo hi"},
	})
	if !contains(string(data), "rate limit") {
		t.Fatalf("3rd call should be rate limited: %s", data)
	}
}

func TestE2ESinkReceivesEvents(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "*", Deny: true},
		{ApplyTo: "read_file", Allow: true},
	}, []RedactRule{
		{Keys: []string{"api_key"}, Pattern: ".*", Replacement: "***"},
	}, nil)

	g, w, r, _ := testGate(t, cp)
	var got []audit.Entry
	g.Sink = func(e audit.Entry) { got = append(got, e) }

	e2eRun(t, w, r, "tools/call", map[string]any{
		"name": "shell", "arguments": map[string]any{"cmd": "ls"},
	})
	e2eRun(t, w, r, "tools/call", map[string]any{
		"name":      "read_file",
		"arguments": map[string]any{"path": "/etc/hosts", "api_key": "sk-hunter2"},
	})

	// The gate's deferred audit fires after the reply is written, so wait
	// for the sink to catch up instead of racing it.
	deadline := time.Now().Add(3 * time.Second)
	for len(got) < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	kinds := map[string]int{}
	for _, e := range got {
		kinds[e.Kind]++
	}
	if kinds["request"] < 2 {
		t.Errorf("sink: request entries = %d, want >= 2", kinds["request"])
	}
	if kinds["blocked"] != 1 {
		t.Errorf("sink: blocked entries = %d, want 1", kinds["blocked"])
	}
	if kinds["response"] != 1 {
		t.Errorf("sink: response entries = %d, want 1", kinds["response"])
	}
	if kinds["redacted"] == 0 {
		t.Error("sink: expected redacted entries for args or response")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
