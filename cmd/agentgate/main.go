package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/gate"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
	"github.com/gunjitdhakar15/AgentGate/internal/web"
	"gopkg.in/yaml.v3"
)

// Config is the on-disk gate configuration.
type Config struct {
	// ToolServer is the real MCP tool server invoked as a child process.
	ToolServer struct {
		Command string   `yaml:"command"`
		Args    []string `yaml:"args"`
	} `yaml:"tool_server"`
	AuditLog string        `yaml:"audit_log"`
	Timeout  time.Duration `yaml:"timeout"`
	Policy   gate.Policy   `yaml:"policy"`
}

func main() {
	var (
		configPath = flag.String("config", "", "path to agentgate.yaml")
		auditPath  = flag.String("audit", "", "audit log path (overrides config)")
		timeout    = flag.Duration("timeout", 10*time.Minute, "per-request timeout")
		showPolicy = flag.Bool("check-config", false, "validate config and print compiled policy, then exit")
		serveAddr  = flag.String("serve", "", "serve the live dashboard on this address (e.g. :8700)")
		demoMode   = flag.Bool("demo", false, "generate self-driven demo traffic for the dashboard (no gate required)")
		withJudge  = flag.Bool("with-judge", false, "enable Tier 1 LLM risk classifier (requires ANTHROPIC_API_KEY)")
		mockJudge  = flag.Bool("mock-judge", false, "enable Tier 1 offline mock risk classifier (no API key required)")
		model      = flag.String("model", "", "override judge model (default: claude-haiku-4-5-20251001)")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Dashboard-only mode: no config, no gate; watch an existing audit log
	// or run synthetic demo traffic.
	if *configPath == "" {
		if *serveAddr == "" {
			fatalf("config: -config path is required (or use -serve for dashboard-only mode)")
		}
		runWatcher(ctx, *serveAddr, *auditPath, *demoMode)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("config: %v", err)
	}

	cp, err := gate.Compile(cfg.Policy)
	if err != nil {
		fatalf("policy: %v", err)
	}

	if *showPolicy {
		fmt.Printf("policy OK: %d tool rules, %d redact rules, %d rate limits\n",
			len(cfg.Policy.ToolRules), len(cfg.Policy.Redact), len(cfg.Policy.RateLimits))
		return
	}

	logPath := cfg.AuditLog
	if *auditPath != "" {
		logPath = *auditPath
	}

	var dash *web.Dashboard
	var httpSrv *http.Server
	if *serveAddr != "" {
		dash = web.New()
		httpSrv = startDashboard(dash, *serveAddr)
		defer httpSrv.Close()
	}

	store, err := audit.Open(logPath)
	if err != nil {
		fatalf("audit: %v", err)
	}
	defer store.Close()

	g := gate.New(cp, store, log.Default())
	if dash != nil {
		g.Sink = dash.Notify
	}
	if *timeout != 10*time.Minute {
		g.Timeout = *timeout
	} else if cfg.Timeout > 0 {
		g.Timeout = cfg.Timeout
	}

	if *mockJudge {
		g.Judge = judge.NewDeterministicMockJudge()
		g.RouterCfg = judge.DefaultRouterConfig()
		g.Approver = judge.NewCLIApprover()
		log.Printf("tier 1 risk classifier: mock active (router: block >= 0.8, review >= 0.4)")
	} else if *withJudge {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			fatalf("-with-judge requires ANTHROPIC_API_KEY to be set (or use -mock-judge for offline evaluation)")
		}
		g.Judge = judge.NewAnthropicJudge(apiKey, *model)
		g.RouterCfg = judge.DefaultRouterConfig()
		g.Approver = judge.NewCLIApprover()
		log.Printf("tier 1 risk classifier: claude haiku active (router: block >= 0.8, review >= 0.4)")
	}

	// The agent talks to us on our own stdio; we talk to the real tool
	// server over pipes.
	agent := mcp.NewStream(os.Stdin, os.Stdout)
	server, cleanup, err := gate.SpawnToolServer(ctx, cfg.ToolServer.Command, cfg.ToolServer.Args)
	if err != nil {
		fatalf("tool server: %v", err)
	}
	defer cleanup()

	log.Printf("agentgate up: %s %v -> audit=%s", cfg.ToolServer.Command, cfg.ToolServer.Args, logPath)
	if err := g.Serve(ctx, agent, server); err != nil && ctx.Err() == nil {
		fatalf("gate: %v", err)
	}
	log.Printf("agentgate exiting")
}

// startDashboard serves the live dashboard in a background goroutine.
func startDashboard(dash *web.Dashboard, addr string) *http.Server {
	srv := &http.Server{Addr: addr, Handler: dash.Handler()}
	go func() {
		log.Printf("dashboard up: http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard: %v", err)
		}
	}()
	return srv
}

// runWatcher runs dashboard-only mode: tail an audit log and serve it, or
// generate synthetic demo traffic when demo is set.
func runWatcher(ctx context.Context, addr, auditPath string, demo bool) {
	dash := web.New()
	if demo {
		StartDemoTraffic(ctx, dash)
		log.Printf("demo traffic: on")
	} else {
		path := auditPath
		if path == "" {
			path = filepath.Join("agentgate-audit.jsonl")
		}
		dash.TailFile(ctx, path)
		log.Printf("watching audit log: %s", path)
	}
	srv := startDashboard(dash, addr)
	<-ctx.Done()
	_ = srv.Close()
	log.Printf("dashboard exiting")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.ToolServer.Command == "" {
		return nil, fmt.Errorf("tool_server.command is required")
	}
	if cfg.AuditLog == "" {
		cfg.AuditLog = filepath.Join("agentgate-audit.jsonl")
	}
	return &cfg, nil
}

func fatalf(format string, a ...any) {
	log.Printf(format, a...)
	os.Exit(1)
}
