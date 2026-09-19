package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
	"github.com/gunjitdhakar15/AgentGate/internal/gate"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
	"github.com/gunjitdhakar15/AgentGate/internal/web"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	// Version metadata
	Version   = "v1.1.0"
	GitCommit = "c5dc2c9"
	BuildDate = "2026-09-20"

	// CLI flags
	cfgFile    string
	logLevel   string
	logFormat  string
	auditPath  string
	serveAddr  string
	timeout    time.Duration
	showPolicy bool
	demoMode   bool
	withJudge  bool
	mockJudge  bool
	modelName  string
)

// Config is the on-disk gate configuration.
type Config struct {
	ToolServer struct {
		Command string   `yaml:"command"`
		Args    []string `yaml:"args"`
	} `yaml:"tool_server"`
	AuditLog string        `yaml:"audit_log"`
	Timeout  time.Duration `yaml:"timeout"`
	Policy   gate.Policy   `yaml:"policy"`
}

var rootCmd = &cobra.Command{
	Use:   "agentgate",
	Short: "AgentGate is a multi-tiered security firewall for AI agent tool calls (MCP)",
	Long: `AgentGate sits transparently between an AI agent (Claude Code, Cursor, Windsurf)
and child tool servers, evaluating semantic risk, enforcing deny-by-default rules,
redacting secrets, rate-limiting, and auditing every single tool invocation.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogging()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Auto-detect Render/Cloud PORT environment variable
		if port := os.Getenv("PORT"); port != "" && serveAddr == "" {
			if !strings.HasPrefix(port, ":") {
				serveAddr = ":" + port
			} else {
				serveAddr = port
			}
		}

		// Dashboard / Demo / Cloud-serve mode:
		if serveAddr != "" || demoMode {
			if serveAddr == "" {
				serveAddr = ":8700"
			}
			runWatcher(ctx, serveAddr, auditPath, demoMode)
			return nil
		}

		if cfgFile == "" {
			cfgFile = "configs/agentgate.yaml"
		}
		return runProxy(ctx)
	},
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run the transparent MCP security proxy between agent and tool server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runProxy(ctx)
	},
}

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Run the standalone live monitoring dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if port := os.Getenv("PORT"); port != "" && serveAddr == "" {
			if !strings.HasPrefix(port, ":") {
				serveAddr = ":" + port
			} else {
				serveAddr = port
			}
		}
		if serveAddr == "" {
			serveAddr = ":8700"
		}
		runWatcher(ctx, serveAddr, auditPath, false)
		return nil
	},
}

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run live web dashboard with synthetic demo firewall traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if port := os.Getenv("PORT"); port != "" && serveAddr == "" {
			if !strings.HasPrefix(port, ":") {
				serveAddr = ":" + port
			} else {
				serveAddr = port
			}
		}
		if serveAddr == "" {
			serveAddr = ":8700"
		}
		runWatcher(ctx, serveAddr, auditPath, true)
		return nil
	},
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Validate agentgate configuration and print compiled policy summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		_, err = gate.Compile(cfg.Policy)
		if err != nil {
			return fmt.Errorf("policy: %w", err)
		}
		fmt.Printf("policy OK: %d tool rules, %d redact rules, %d rate limits\n",
			len(cfg.Policy.ToolRules), len(cfg.Policy.Redact), len(cfg.Policy.RateLimits))
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print build version and runtime environment info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AgentGate %s (commit: %s, built: %s, go: %s %s/%s)\n",
			Version, GitCommit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Persistent flags (available on all subcommands)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "configs/agentgate.yaml", "Path to configuration file")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "Log format (text, json)")

	// Proxy & Execution flags
	rootCmd.PersistentFlags().StringVar(&auditPath, "audit", "", "Audit log path (overrides config)")
	rootCmd.PersistentFlags().StringVar(&serveAddr, "serve", "", "Serve the live dashboard on address (e.g. :8700)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Minute, "Per-request timeout")
	rootCmd.PersistentFlags().BoolVar(&showPolicy, "check-config", false, "Validate config and print compiled policy, then exit")
	rootCmd.PersistentFlags().BoolVar(&demoMode, "demo", false, "Generate self-driven demo traffic for dashboard")
	rootCmd.PersistentFlags().BoolVar(&withJudge, "with-judge", false, "Enable Tier 1 LLM risk classifier (requires ANTHROPIC_API_KEY)")
	rootCmd.PersistentFlags().BoolVar(&mockJudge, "mock-judge", false, "Enable Tier 1 offline mock risk classifier (no API key required)")
	rootCmd.PersistentFlags().StringVar(&modelName, "model", "", "Override judge model (default: claude-haiku-4-5-20251001)")

	// Bind Viper keys
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("audit.path", rootCmd.PersistentFlags().Lookup("audit"))
	_ = viper.BindPFlag("serve", rootCmd.PersistentFlags().Lookup("serve"))

	// Subcommands
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(dashboardCmd)
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
		viper.SetConfigName("agentgate")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("AGENTGATE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}

func initLogging() error {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q (valid: debug, info, warn, error)", logLevel)
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(logFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func runProxy(ctx context.Context) error {
	cfg, err := loadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	cp, err := gate.Compile(cfg.Policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	if showPolicy {
		fmt.Printf("policy OK: %d tool rules, %d redact rules, %d rate limits\n",
			len(cfg.Policy.ToolRules), len(cfg.Policy.Redact), len(cfg.Policy.RateLimits))
		return nil
	}

	logPath := cfg.AuditLog
	if auditPath != "" {
		logPath = auditPath
	}

	var dash *web.Dashboard
	var httpSrv *http.Server
	if serveAddr != "" {
		dash = web.New()
		httpSrv = startDashboard(dash, serveAddr)
		defer httpSrv.Close()
	}

	store, err := audit.Open(logPath)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer store.Close()

	g := gate.New(cp, store, nil)
	if dash != nil {
		g.Sink = dash.Notify
	}
	if timeout != 10*time.Minute {
		g.Timeout = timeout
	} else if cfg.Timeout > 0 {
		g.Timeout = cfg.Timeout
	}

	if mockJudge {
		g.Judge = judge.NewDeterministicMockJudge()
		g.RouterCfg = judge.DefaultRouterConfig()
		g.Approver = judge.NewCLIApprover()
		slog.Info("tier 1 risk classifier active", "type", "mock", "router", "block >= 0.8, review >= 0.4")
	} else if withJudge {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return fmt.Errorf("--with-judge requires ANTHROPIC_API_KEY to be set (or use --mock-judge for offline evaluation)")
		}
		g.Judge = judge.NewAnthropicJudge(apiKey, modelName)
		g.RouterCfg = judge.DefaultRouterConfig()
		g.Approver = judge.NewCLIApprover()
		slog.Info("tier 1 risk classifier active", "type", "claude-haiku", "router", "block >= 0.8, review >= 0.4")
	}

	agent := mcp.NewStream(os.Stdin, os.Stdout)
	server, cleanup, err := gate.SpawnToolServer(ctx, cfg.ToolServer.Command, cfg.ToolServer.Args)
	if err != nil {
		return fmt.Errorf("tool server: %w", err)
	}
	defer cleanup()

	slog.Info("agentgate proxy active", "command", cfg.ToolServer.Command, "args", cfg.ToolServer.Args, "audit", logPath)
	if err := g.Serve(ctx, agent, server); err != nil && ctx.Err() == nil {
		return fmt.Errorf("gate: %w", err)
	}
	slog.Info("agentgate exiting")
	return nil
}

func startDashboard(dash *web.Dashboard, addr string) *http.Server {
	srv := &http.Server{Addr: addr, Handler: dash.Handler()}
	go func() {
		slog.Info("dashboard running", "url", fmt.Sprintf("http://%s", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("dashboard error", "err", err)
		}
	}()
	return srv
}

func runWatcher(ctx context.Context, addr, auditLogPath string, demo bool) {
	dash := web.New()
	if demo {
		StartDemoTraffic(ctx, dash)
		slog.Info("demo traffic started")
	} else {
		path := auditLogPath
		if path == "" {
			path = filepath.Join("agentgate-audit.jsonl")
		}
		dash.TailFile(ctx, path)
		slog.Info("watching audit log", "path", path)
	}
	srv := startDashboard(dash, addr)
	<-ctx.Done()
	_ = srv.Close()
	slog.Info("dashboard exiting")
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