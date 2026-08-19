package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
)

// Gate proxies an MCP stdio session between an agent and a tool server,
// enforcing policy on tools/call, redacting secrets from what the agent and
// the audit log see, and recording everything.
type Gate struct {
	Policy *compiledPolicy
	Audit  *audit.Store
	// Timeout per forwarded request; 0 uses the default of 10 minutes.
	Timeout time.Duration
	// Sink, when set, receives every audit entry in addition to the store.
	Sink func(audit.Entry)

	log     *log.Logger
	buckets []*bucketRule
}

type bucketRule struct {
	applyTo string
	b       *TokenBucket
}

// New builds a gate from a compiled policy.
func New(cp *compiledPolicy, a *audit.Store, logger *log.Logger) *Gate {
	if logger == nil {
		logger = log.Default()
	}
	g := &Gate{Policy: cp, Audit: a, log: logger}
	for _, rl := range cp.p.RateLimits {
		g.buckets = append(g.buckets, &bucketRule{applyTo: rl.ApplyTo, b: NewRateLimiter(rl.Burst, rl.Window)})
	}
	return g
}

// Compile validates and pre-compiles a policy.
func Compile(p Policy) (*compiledPolicy, error) { return compilePolicy(p) }

// Serve proxies the MCP session until the agent closes the stream or ctx is
// cancelled. The stdio transport is strictly sequential: the agent sends a
// request and waits for the reply, so we serialize everything in one loop.
func (g *Gate) Serve(ctx context.Context, agent, server *mcp.Stream) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := agent.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read from agent: %w", err)
		}

		switch mcp.ObjectKind(data) {
		case mcp.KindRequest:
			req, err := mcp.ParseRequest(data)
			if err != nil {
				return fmt.Errorf("bad request from agent: %w", err)
			}
			if err := g.handleRequest(ctx, req, data, agent, server); err != nil {
				return err
			}
		case mcp.KindNotification:
			// Fire-and-forget; forward verbatim without waiting for a reply.
			if err := server.WriteRaw(data); err != nil {
				return fmt.Errorf("forward notification: %w", err)
			}
		case mcp.KindResponse:
			g.auditErr("protocol", "unexpected response sent by agent")
		default:
			g.auditErr("protocol", "unparseable agent message dropped")
		}
	}
}

func (g *Gate) handleRequest(ctx context.Context, req *mcp.Request, raw []byte, agent, server *mcp.Stream) error {
	start := time.Now()
	defer func() {
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "request", RequestID: req.IDString(),
			Method: req.Method, Duration: time.Since(start),
		})
	}()

	// Policy applies only to tool invocations; every other MCP method passes
	// through untouched.
	if req.Method != "tools/call" {
		return g.forwardRelay(ctx, req, raw, agent, server)
	}

	call, err := parseToolCall(req)
	if err != nil {
		return g.respondErr(agent, req.ID, -32602, err.Error())
	}

	// Rate limiting.
	if !g.rateAllowed(call.Name) {
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "blocked", RequestID: req.IDString(),
			Method: req.Method, Tool: call.Name, Decision: "rate limit exceeded",
		})
		return g.respondBlocked(agent, req.ID, call.Name, "rate limit exceeded")
	}

	// Policy decision + redaction.
	rawArgs := mustJSON(call.Arguments)
	dec, redacted := g.Policy.Check(call.Name, call.Arguments)
	if !dec.Allowed {
		g.log.Printf("blocked tool=%q reason=%q rule=%q", call.Name, dec.Reason, dec.Rule)
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "blocked", RequestID: req.IDString(),
			Method: req.Method, Tool: call.Name, Decision: dec.Reason,
			Args: mustJSON(redacted),
		})
		return g.respondBlocked(agent, req.ID, call.Name, dec.Reason)
	}

	redactedArgs := mustJSON(redacted)
	if string(redactedArgs) != string(rawArgs) {
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "redacted", RequestID: req.IDString(),
			Method: req.Method, Tool: call.Name, Decision: "arguments",
			Args: redactedArgs,
		})
	}

	// Forward the sanitized call.
	sanitized, _ := json.Marshal(map[string]any{
		"name":      call.Name,
		"arguments": redacted,
	})
	fwd := mcp.Request{JSONRPC: "2.0", ID: req.ID, Method: "tools/call", Params: sanitized}
	if err := server.Write(fwd); err != nil {
		return fmt.Errorf("forward tools/call: %w", err)
	}

	// Read the single reply for this request.
	resp, err := g.readReply(ctx, server)
	if err != nil {
		return err
	}

	// Redact the response payload before it reaches the agent or the log.
	if len(resp.Result) > 0 {
		redactedResult := g.RedactPayload(resp.Result)
		if string(redactedResult) != string(resp.Result) {
			g.audit(audit.Entry{
				TS: time.Now(), Kind: "redacted", RequestID: req.IDString(),
				Method: req.Method, Tool: call.Name, Decision: "response",
				Result: redactedResult,
			})
		}
		resp.Result = redactedResult
	}
	g.audit(audit.Entry{
		TS: time.Now(), Kind: "response", RequestID: req.IDString(),
		Method: req.Method, Tool: call.Name, Result: resp.Result,
	})
	return agent.Write(resp)
}

// forwardRelay sends a non-policy request downstream and relays the reply.
func (g *Gate) forwardRelay(ctx context.Context, req *mcp.Request, raw []byte, agent, server *mcp.Stream) error {
	if err := server.WriteRaw(raw); err != nil {
		return fmt.Errorf("forward %s: %w", req.Method, err)
	}
	resp, err := g.readReply(ctx, server)
	if err != nil {
		return err
	}
	return agent.Write(resp)
}

// readReply reads exactly one response message from the tool server.
func (g *Gate) readReply(ctx context.Context, server *mcp.Stream) (*mcp.Response, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	done := make(chan *mcp.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		data, err := server.Read()
		if err != nil {
			errCh <- err
			return
		}
		resp, err := mcp.ParseResponse(data)
		if err != nil {
			errCh <- err
			return
		}
		done <- resp
	}()

	select {
	case resp := <-done:
		return resp, nil
	case err := <-errCh:
		return nil, fmt.Errorf("read reply: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for tool server reply")
	}
}

// RedactPayload masks redaction patterns in string values of a JSON payload.
// Malformed payloads pass through untouched.
func (g *Gate) RedactPayload(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	v = redactValue(v, g.Policy.redacts)
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// rateAllowed enforces the policy rate limits for a tool.
func (g *Gate) rateAllowed(tool string) bool {
	allowed := true
	for _, r := range g.buckets {
		if r.applyTo == "" || r.applyTo == "*" || stringsEqualFold(r.applyTo, tool) {
			if !r.b.Allow(tool) {
				allowed = false
			}
		}
	}
	return allowed
}

func (g *Gate) respondBlocked(agent *mcp.Stream, id json.RawMessage, tool, reason string) error {
	return agent.Write(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  mcp.BlockedResult(fmt.Sprintf("%s: %s", tool, reason)),
	})
}

func (g *Gate) respondErr(agent *mcp.Stream, id json.RawMessage, code int, msg string) error {
	return agent.Write(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &mcp.RPCError{Code: code, Message: msg},
	})
}

func (g *Gate) audit(e audit.Entry) {
	if g.Audit != nil {
		_ = g.Audit.Log(e)
	}
	if g.Sink != nil {
		g.Sink(e)
	}
}

func (g *Gate) auditErr(kind, msg string) {
	g.audit(audit.Entry{TS: time.Now(), Kind: kind, Error: msg})
}

// ToolCall is a decoded tools/call invocation.
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// parseToolCall extracts the tool name and arguments from tools/call params.
func parseToolCall(req *mcp.Request) (ToolCall, error) {
	var call ToolCall
	if err := json.Unmarshal(req.Params, &call); err != nil {
		return call, fmt.Errorf("invalid tools/call params")
	}
	if call.Name == "" {
		return call, fmt.Errorf("missing tool name")
	}
	return call, nil
}

// SpawnToolServer starts the real MCP tool server as a child process and
// returns its stdio stream. The returned cleanup waits for process exit.
func SpawnToolServer(ctx context.Context, bin string, args []string) (*mcp.Stream, func(), error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start tool server: %w", err)
	}
	cleanup := func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}
	return mcp.NewStream(stdout, stdin), cleanup, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && a[i]|0x20 != b[i]|0x20 {
			return false
		}
	}
	return true
}
