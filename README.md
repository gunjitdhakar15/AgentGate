# AgentGate

An MCP (Model Context Protocol) **security firewall** for AI agents.

`AgentGate` sits between your agent (Claude Code, Cursor, or any MCP client)
and a real tool server, enforcing policy, redacting secrets, rate-limiting,
and auditing every single call — before it ever reaches the tool.

```
┌──────────┐   tools/call   ┌────────────┐   tools/call   ┌──────────────┐
│  Agent   │ ─────────────► │ AgentGate  │ ─────────────► │ Tool server  │
│ (client) │ ◄───────────── │  firewall  │ ◄───────────── │  (child)     │
└──────────┘    response    └────────────┘    response    └──────────────┘
                            │ policy • redact • rate-limit
                            ▼
                         audit.jsonl (JSONL, secrets stripped)
```

## Why

Agents can now run shell commands, write files, and hit network endpoints.
A hijacked prompt is all it takes to turn a benign tool into a weapon.
AgentGate makes that impossible to do silently: every tool call is checked,
sanitized, and recorded.

## Install & run

```bash
go build -o agentgate ./cmd/agentgate

# Wrap any MCP stdio server with a policy
./agentgate -config configs/agentgate.yaml
```

Point your MCP client at `agentgate` instead of the real server binary —
nothing else changes.

## Pipeline

For every `tools/call` request:

1. **Rate limit** — token-bucket per tool (e.g. 5 shell calls/minute).
2. **Policy check**:
   - deny-by-default with explicit `allow` overrides;
   - argument patterns are a hard safety net (`rm -rf` never runs);
   - oversized argument payloads are rejected.
3. **Redaction** — secrets in *arguments* are masked before the call is
   forwarded, and the *response* is masked before it reaches the agent.
   Nested JSON is walked; patterns may be scoped to specific keys.
4. **Audit** — every request, response, and block is written to a JSONL log
   (with secrets already stripped), replayable for incident review.

Everything else in the MCP protocol (`initialize`, `tools/list`, resources,
prompts, notifications) passes through untouched.

## Example policy

```yaml
tool_server:
  command: npx
  args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

policy:
  tool_rules:
    - apply_to: "*"
      deny: true
      reason: "deny all tools by default"
    - apply_to: read_file
      allow: true
    - apply_to: shell
      allow: true
      arg_deny_pattern: "(rm -rf|del /s|shutdown|format )"
      reason: "dangerous shell commands blocked"
    - apply_to: write_file
      deny: true
  redact:
    - keys: ["api_key", "password", "token"]
      pattern: ".*"
      replacement: "***"
    - pattern: "Bearer\\s+[A-Za-z0-9._-]{10,}"
      replacement: "Bearer ***"
  rate_limits:
    - apply_to: shell
      burst: 5
      window: 1m
  max_arg_bytes: 65536
```

## CLI

```bash
agentgate -config gate.yaml          # run the firewall
agentgate -config gate.yaml -serve :8700   # run the firewall + live dashboard
agentgate -serve :8700 -audit gate.jsonl   # dashboard-only: tail an existing audit log
agentgate -check-config              # validate policy, then exit
agentgate -audit /tmp/gate.log       # override audit path
```

## Live dashboard

Open `http://localhost:8700` in a browser while the gate runs and watch every
policy decision in real time:

- **live counters** — requests, allowed, blocked, secrets redacted, protocol errors;
- **allow/block donut** and **per-tool bars**;
- **audit feed** streamed over SSE, with the reason every call was blocked and
  redacted payloads (no secrets, ever).

Attach the dashboard to a running gate in two ways:

```bash
# 1. Same process: gate + dashboard together
./agentgate -config configs/agentgate.yaml -serve :8700

# 2. Separately: watch the audit log of an already-running gate
./agentgate -serve :8700 -audit agentgate-audit.jsonl
```

## Layout

```
cmd/agentgate/     CLI entrypoint + config loading + live dashboard server
internal/mcp/      JSON-RPC 2.0 framing, stdio transport
internal/gate/     policy engine, redaction, rate limiting, proxy core
internal/audit/    JSONL audit store with replay
internal/web/      live dashboard (SSE + embedded UI)
configs/           example policies
```

## Tests

```bash
go test ./...
```

Covers policy semantics, redaction (incl. nested JSON), rate limiting,
audit replay, protocol framing, and end-to-end proxy behavior against an
in-process fake tool server.