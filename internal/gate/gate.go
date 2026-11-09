package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
)

// historyWindow caps how many recent tool calls are kept for the Tier 1
// judge's session-context (escalation-pattern) awareness. Small on purpose:
// this rides on every judged call, so it stays cheap.
const historyWindow = 8

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

	// Judge, when non-nil, runs Tier 1 semantic risk assessment on every
	// call Tier 0 (Policy) allowed. Nil means Tier 0 only — this makes it
	// possible to run the eval harness against both configurations from
	// the same binary by simply not constructing a Judge.
	Judge     judge.Judge
	RouterCfg judge.RouterConfig
	Approver  judge.Approver
	// JudgeTimeout bounds a single Tier 1 assessment. 0 disables the extra
	// deadline (the provider's own HTTP timeout still applies).
	JudgeTimeout time.Duration
	// TaskContext is passed to the judge as the agent's stated goal, if
	// the operator has one to give (e.g. set from the session's initial
	// prompt). Optional.
	TaskContext string

	log     *log.Logger
	buckets []*bucketRule
	history []string // rolling window of recent "tool(argsSummary)" strings, this session only

	// serverMsgs carries frames from the single long-lived reader that owns
	// the tool-server stream. See Serve.
	serverMsgs <-chan serverMessage
}

// serverMessage is one frame (or terminal error) read from the tool server.
type serverMessage struct {
	data []byte
	err  error
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
	// Exactly one goroutine owns reads from the tool server for the lifetime
	// of the session. Reading per-request leaks a goroutine when a request
	// times out, and that leaked reader can then steal the reply belonging to
	// the next request. A single reader feeds a channel instead; replies are
	// matched to the request ID below.
	msgs := make(chan serverMessage, 32)
	g.serverMsgs = msgs
	go func() {
		for {
			data, err := server.Read()
			select {
			case msgs <- serverMessage{data: data, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				close(msgs)
				return
			}
		}
	}()

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

	// Tier 1: semantic risk assessment. Only runs on calls Tier 0 already
	// allowed — Tier 0's deny-by-default and hard argument-pattern guards
	// still apply first and cannot be overridden by the judge.
	if g.Judge != nil {
		if blocked, err := g.runJudge(ctx, req, agent, call.Name, redacted); err != nil {
			return err
		} else if blocked {
			return nil
		}
	}
	g.pushHistory(call.Name, redacted)

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
	resp, err := g.readReply(ctx, agent, req.ID)
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

// runJudge runs Tier 1 on a call Tier 0 already allowed. It returns
// blocked=true if the gate has already responded to the agent (either a
// denial or a failed approval) and the caller should stop processing this
// request; err is non-nil only for a transport-level failure while
// responding.
func (g *Gate) runJudge(ctx context.Context, req *mcp.Request, agent *mcp.Stream, tool string, args map[string]any) (blocked bool, err error) {
	assessCtx := ctx
	if g.JudgeTimeout > 0 {
		var cancel context.CancelFunc
		assessCtx, cancel = context.WithTimeout(ctx, g.JudgeTimeout)
		defer cancel()
	}
	verdict, jerr := g.Judge.Assess(assessCtx, judge.ToolCallContext{
		Tool: tool, Arguments: args, TaskContext: g.TaskContext, RecentHistory: g.history,
	})

	var route judge.Route
	if jerr != nil {
		route = judge.RouteOnError(g.RouterCfg, tool)
		g.log.Printf("judge error tool=%q err=%v -> route=%s", tool, jerr, route)
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "judge_error", RequestID: req.IDString(),
			Method: req.Method, Tool: tool, Decision: string(route), Error: jerr.Error(),
		})
	} else {
		route = judge.RouteVerdict(g.RouterCfg, verdict)
		g.audit(audit.Entry{
			TS: time.Now(), Kind: "judge_verdict", RequestID: req.IDString(),
			Method: req.Method, Tool: tool, Decision: string(route),
			Args: mustJSON(map[string]any{
				"risk_score": verdict.RiskScore,
				"category":   verdict.Category,
				"rationale":  verdict.Rationale,
			}),
		})
	}

	switch route {
	case judge.RouteAllow:
		return false, nil

	case judge.RouteNeedsApproval:
		if g.Approver == nil {
			// No approval channel configured: treat like a plain block
			// rather than silently auto-allowing a flagged call.
			return true, g.respondBlocked(agent, req.ID, tool, "requires human approval, no approver configured")
		}
		approved, aerr := g.Approver.RequestApproval(ctx, judge.ToolCallContext{Tool: tool, Arguments: args}, verdict)
		if aerr != nil {
			g.log.Printf("approval channel error tool=%q err=%v", tool, aerr)
			return true, g.respondErr(agent, req.ID, -32000, "approval channel error")
		}
		if !approved {
			g.audit(audit.Entry{TS: time.Now(), Kind: "blocked", RequestID: req.IDString(), Method: req.Method, Tool: tool, Decision: "human reviewer denied"})
			return true, g.respondBlocked(agent, req.ID, tool, "human reviewer denied")
		}
		return false, nil

	default: // judge.RouteBlock
		reason := verdict.Rationale
		if jerr != nil {
			reason = "judge unavailable, tool requires a semantic risk check"
		}
		g.audit(audit.Entry{TS: time.Now(), Kind: "blocked", RequestID: req.IDString(), Method: req.Method, Tool: tool, Decision: reason})
		return true, g.respondBlocked(agent, req.ID, tool, reason)
	}
}

// pushHistory records a call in the session's rolling history window, used
// as escalation-pattern context for future judge calls.
func (g *Gate) pushHistory(tool string, args map[string]any) {
	b, _ := json.Marshal(args)
	g.history = append(g.history, tool+"("+string(b)+")")
	if len(g.history) > historyWindow {
		g.history = g.history[len(g.history)-historyWindow:]
	}
}

// forwardRelay sends a non-policy request downstream and relays the reply.
func (g *Gate) forwardRelay(ctx context.Context, req *mcp.Request, raw []byte, agent, server *mcp.Stream) error {
	if err := server.WriteRaw(raw); err != nil {
		return fmt.Errorf("forward %s: %w", req.Method, err)
	}
	resp, err := g.readReply(ctx, agent, req.ID)
	if err != nil {
		return err
	}
	return agent.Write(resp)
}

// readReply reads the response for expectedID from the tool server, relaying
// any intermediate notifications back to the agent. Replies whose id does not
// match are stale (e.g. a late answer to a request that already timed out)
// and are dropped rather than handed to the wrong caller.
func (g *Gate) readReply(ctx context.Context, agent *mcp.Stream, expectedID json.RawMessage) (*mcp.Response, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg, ok := <-g.serverMsgs:
			if !ok {
				return nil, io.EOF
			}
			if msg.err != nil {
				return nil, fmt.Errorf("read reply: %w", msg.err)
			}
			if mcp.ObjectKind(msg.data) == mcp.KindNotification {
				// Relay tool server notification (e.g. progress, logs) to the agent.
				if agent != nil {
					_ = agent.WriteRaw(msg.data)
				}
				continue
			}
			resp, err := mcp.ParseResponse(msg.data)
			if err != nil {
				return nil, err
			}
			if !sameJSONID(resp.ID, expectedID) {
				g.log.Printf("dropping stale response id=%s expected=%s", string(resp.ID), string(expectedID))
				continue
			}
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("timed out waiting for tool server reply (%v)", timeout)
		}
	}
}

// sameJSONID compares two JSON-RPC ids, tolerating formatting differences
// between numeric and string encodings.
func sameJSONID(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return string(a) == string(b)
	}
	return fmt.Sprintf("%v", av) == fmt.Sprintf("%v", bv)
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

// RateAllowed reports whether the rate limit permits a call for this tool.
func (g *Gate) RateAllowed(tool string) bool {
	return g.rateAllowed(tool)
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
	cmd.Stderr = os.Stderr
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
	return strings.EqualFold(a, b)
}
