package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/gate"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
)

//go:embed assets
var assets embed.FS

var (
	defaultPolicy *gate.Gate
	mockJudge     *judge.MockJudge
	routerCfg     judge.RouterConfig
)

func init() {
	p := gate.Policy{
		ToolRules: []gate.ToolRule{
			{ApplyTo: "*", Deny: true, Reason: "deny all tools by default"},
			{ApplyTo: "read_file", Allow: true},
			{ApplyTo: "list_directory", Allow: true},
			{ApplyTo: "search_files", Allow: true},
			{ApplyTo: "http_get", Allow: true},
			{ApplyTo: "shell", Allow: true, ArgDenyPattern: "(rm -rf|del /s|shutdown|format )", Reason: "destructive shell commands blocked by tier 0"},
			{ApplyTo: "write_file", Deny: true, Reason: "read-only filesystem mode"},
		},
		Redact: []gate.RedactRule{
			{Keys: []string{"api_key", "password", "token", "secret", "authorization"}, Pattern: ".*", Replacement: "***"},
			{Pattern: "sk-[A-Za-z0-9]{20,}", Replacement: "***"},
			{Pattern: "Bearer\\s+[A-Za-z0-9._-]{10,}", Replacement: "Bearer ***"},
		},
		RateLimits: []gate.RateLimit{
			{ApplyTo: "shell", Burst: 5, Window: time.Minute},
		},
	}
	cp, _ := gate.Compile(p)
	defaultPolicy = gate.New(cp, nil, nil)
	mockJudge = judge.NewDeterministicMockJudge()
	routerCfg = judge.DefaultRouterConfig()
}

// Handler builds the dashboard HTTP routes: the landing page, the live
// dashboard, stats, evaluation API, and the SSE event stream.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleLanding)
	mux.HandleFunc("/dashboard", d.handleDashboard)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/evaluate", d.handleEvaluate)
	mux.HandleFunc("/events", d.handleSSE)
	return mux
}

func (d *Dashboard) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d.serveAsset(w, "assets/landing.html", "text/html; charset=utf-8")
}

func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	d.serveAsset(w, "assets/dashboard.html", "text/html; charset=utf-8")
}

func (d *Dashboard) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(d.Snapshot())
}

type EvalRequest struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

type EvalResponse struct {
	Tool           string         `json:"tool"`
	RawArgs        map[string]any `json:"raw_args"`
	RedactedArgs   map[string]any `json:"redacted_args"`
	Tier0Allowed   bool           `json:"tier0_allowed"`
	Tier0Reason    string         `json:"tier0_reason"`
	Tier0Rule      string         `json:"tier0_rule"`
	Tier0LatencyUs int64          `json:"tier0_latency_us"`
	Tier1Ran       bool           `json:"tier1_ran"`
	RiskScore      float64        `json:"risk_score"`
	Category       string         `json:"category"`
	Rationale      string         `json:"rationale"`
	Tier1LatencyUs int64          `json:"tier1_latency_us"`
	Route          string         `json:"route"`
	FinalVerdict   string         `json:"final_verdict"`
	TotalLatencyUs int64          `json:"total_latency_us"`
	StopAt         string         `json:"stop_at"`
	BlockedNode    string         `json:"blocked_node,omitempty"`
}

func (d *Dashboard) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	if req.Tool == "" {
		req.Tool = "shell"
	}
	if req.Arguments == nil {
		req.Arguments = make(map[string]any)
	}

	startTotal := time.Now()

	// 1. Rate Limiter (Token Bucket)
	startRate := time.Now()
	if !defaultPolicy.RateAllowed(req.Tool) {
		rateLatency := time.Since(startRate)
		resp := EvalResponse{
			Tool:           req.Tool,
			RawArgs:        req.Arguments,
			RedactedArgs:   req.Arguments,
			Tier0Allowed:   false,
			Tier0Reason:    "rate limit exceeded",
			Tier0Rule:      "burst capacity reached",
			Route:          "block",
			FinalVerdict:   "RATE_LIMITED",
			StopAt:         "node-rate",
			BlockedNode:    "node-rate",
			Rationale:      "Token-bucket rate limiter exhausted: burst limit reached for tool.",
			TotalLatencyUs: time.Since(startTotal).Microseconds(),
		}

		b, _ := json.Marshal(req.Arguments)
		d.Notify(audit.Entry{
			TS:        time.Now(),
			Kind:      "blocked",
			Tool:      req.Tool,
			Decision:  "rate limit exceeded",
			Args:      b,
			Duration:  rateLatency,
			RequestID: fmt.Sprintf("eval-%d", time.Now().UnixNano()%10000),
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// 2. Tier 0 Policy Check & Redaction
	startT0 := time.Now()
	dec, redacted := defaultPolicy.Policy.Check(req.Tool, req.Arguments)
	tier0Latency := time.Since(startT0)

	resp := EvalResponse{
		Tool:           req.Tool,
		RawArgs:        req.Arguments,
		RedactedArgs:   redacted,
		Tier0Allowed:   dec.Allowed,
		Tier0Reason:    dec.Reason,
		Tier0Rule:      dec.Rule,
		Tier0LatencyUs: tier0Latency.Microseconds(),
	}

	if !dec.Allowed {
		resp.Route = "block"
		resp.FinalVerdict = "BLOCK"
		resp.StopAt = "node-tier0"
		resp.BlockedNode = "node-tier0"
		resp.Rationale = dec.Reason
		resp.TotalLatencyUs = time.Since(startTotal).Microseconds()

		// Record in audit feed
		b, _ := json.Marshal(redacted)
		d.Notify(audit.Entry{
			TS:        time.Now(),
			Kind:      "blocked",
			Tool:      req.Tool,
			Decision:  dec.Reason,
			Args:      b,
			Duration:  tier0Latency,
			RequestID: fmt.Sprintf("eval-%d", time.Now().UnixNano()%10000),
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// 2. Tier 1 Semantic Judge
	resp.Tier1Ran = true
	startT1 := time.Now()
	verdict, _ := mockJudge.Assess(context.Background(), judge.ToolCallContext{
		Tool:      req.Tool,
		Arguments: redacted,
	})
	tier1Latency := time.Since(startT1)
	resp.Tier1LatencyUs = tier1Latency.Microseconds()
	resp.RiskScore = verdict.RiskScore
	resp.Category = string(verdict.Category)
	resp.Rationale = verdict.Rationale

	route := judge.RouteVerdict(routerCfg, verdict)
	resp.Route = string(route)

	switch route {
	case judge.RouteBlock:
		resp.FinalVerdict = "BLOCK"
		resp.StopAt = "node-router"
		resp.BlockedNode = "node-judge"
	case judge.RouteNeedsApproval:
		resp.FinalVerdict = "REVIEW"
		resp.StopAt = "node-router"
		resp.BlockedNode = "node-router"
	default: // RouteAllow
		resp.FinalVerdict = "ALLOW"
		resp.StopAt = "node-server"
		resp.BlockedNode = ""
	}

	resp.TotalLatencyUs = time.Since(startTotal).Microseconds()

	// 3. Emit Audit Entry to SSE
	rawJSON, _ := json.Marshal(req.Arguments)
	redJSON, _ := json.Marshal(redacted)
	kind := "response"
	if resp.FinalVerdict == "BLOCK" {
		kind = "blocked"
	} else if string(rawJSON) != string(redJSON) {
		kind = "redacted"
	}

	d.Notify(audit.Entry{
		TS:        time.Now(),
		Kind:      kind,
		Tool:      req.Tool,
		Decision:  verdict.Rationale,
		Args:      redJSON,
		Duration:  time.Since(startTotal),
		RequestID: fmt.Sprintf("eval-%d", time.Now().UnixNano()%10000),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	writeEvent := func(eType string, payload []byte) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eType, payload)
		flusher.Flush()
	}

	initial, _ := json.Marshal(event{Type: "snapshot", Data: d.snapshotObject()})
	writeEvent("snapshot", initial)

	ch, done := d.Subscribe()
	defer done()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case ev := <-ch:
			b, _ := json.Marshal(ev)
			writeEvent(ev.Type, b)
		case <-tick.C:
			snap, _ := json.Marshal(event{Type: "snapshot", Data: d.snapshotObject()})
			writeEvent("snapshot", snap)
		case <-r.Context().Done():
			return
		}
	}
}
