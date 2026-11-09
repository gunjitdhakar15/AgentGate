package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
	Version   = "v2.0.0"
	GitCommit = "v2-release"
	BuildDate = "2026-10-28"

	// CLI flags
	cfgFile       string
	logLevel      string
	logFormat     string
	auditPath     string
	serveAddr     string
	timeout       time.Duration
	showPolicy    bool
	demoMode      bool
	withJudge     bool
	mockJudge     bool
	judgeProvider string
	modelName     string
	providerKey   string
	providerURL   string
	approvalMode  string
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
	Judge    JudgeConfig   `yaml:"judge"`
}

// JudgeConfig is the Tier 1 semantic-judge section of the YAML config.
// An empty Provider leaves Tier 1 disabled; flags still override the file.
type JudgeConfig struct {
	Provider        string        `yaml:"provider"`
	Model           string        `yaml:"model"`
	APIURL          string        `yaml:"api_url"`
	BlockThreshold  float64       `yaml:"block_threshold"`
	ReviewThreshold float64       `yaml:"review_threshold"`
	// FailOpen is a pointer so an explicit `fail_open: false` is distinguishable
	// from the field being absent (which should keep the default).
	FailOpen      *bool         `yaml:"fail_open"`
	HighRiskTools []string      `yaml:"high_risk_tools"`
	Timeout       time.Duration `yaml:"timeout"`
	// Approval selects the human-in-the-loop channel: auto, cli, web, or deny.
	// auto uses web when the dashboard is served, otherwise cli.
	Approval string `yaml:"approval"`
}

// judgeSettings is the resolved Tier 1 configuration after merging flags,
// environment, and the YAML file.
type judgeSettings struct {
	Provider string
	Model    string
	APIKey   string
	APIURL   string
	Approval string
	Timeout  time.Duration
	Router   judge.RouterConfig
}


func isInteractiveTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

var rootCmd = &cobra.Command{
	Use:   "agentgate",
	Short: "AgentGate is a multi-tiered security firewall for AI agent tool calls (MCP)",
	Long: `AgentGate v2 sits transparently between an AI agent (Claude Code, Cursor, Windsurf)
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

		// Standalone demo mode: generate self-driven demo traffic for web dashboard
		if demoMode {
			if serveAddr == "" {
				serveAddr = ":8700"
			}
			return runWatcher(ctx, serveAddr, auditPath, true)
		}

		// If running in an interactive terminal with no piped input and no explicit serve/proxy command,
		// launch the Decision Studio Cockpit with demo traffic so the user gets an instant, working UI!
		if isInteractiveTerminal() && serveAddr == "" && cfgFile == "configs/agentgate.yaml" {
			fmt.Println("")
			fmt.Println("=======================================================")
			fmt.Println("  ⚡ AgentGate v2 — AI Agent Security Firewall")
			fmt.Println("=======================================================")
			fmt.Println("  Interactive terminal detected without piped MCP stream.")
			fmt.Println("  Launching Decision Studio Cockpit in interactive mode...")
			fmt.Println("  Cockpit: http://localhost:8700/dashboard")
			fmt.Println("  Landing: http://localhost:8700/")
			fmt.Println("")
			fmt.Println("  [Tip] To run as MCP stdio proxy for Claude/Cursor/Windsurf:")
			fmt.Println("        agentgate proxy")
			fmt.Println("=======================================================")
			fmt.Println("")
			return runWatcher(ctx, ":8700", auditPath, true)
		}

		if cfgFile == "" {
			cfgFile = "configs/agentgate.yaml"
		}
		return runProxy(ctx, cmd)
	},
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run the transparent MCP security proxy between agent and tool server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runProxy(ctx, cmd)
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
		return runWatcher(ctx, serveAddr, auditPath, false)
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
		return runWatcher(ctx, serveAddr, auditPath, true)
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

		js, err := resolveJudge(cfg, cmd)
		if err != nil {
			return fmt.Errorf("judge: %w", err)
		}
		if js == nil {
			fmt.Println("judge   : disabled (tier 0 only)")
		} else {
			fmt.Printf("judge   : provider=%s approval=%s block>=%.2f review>=%.2f fail_open=%v\n",
				js.Provider, js.Approval, js.Router.BlockThreshold, js.Router.ReviewThreshold, js.Router.FailOpen)
		}
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
	rootCmd.PersistentFlags().BoolVar(&withJudge, "with-judge", false, "Enable Tier 1 LLM risk classifier")
	rootCmd.PersistentFlags().BoolVar(&mockJudge, "mock-judge", false, "Enable Tier 1 offline mock risk classifier")
	rootCmd.PersistentFlags().StringVar(&judgeProvider, "judge-provider", "", "Judge provider (anthropic, openai, gemini, ollama, mock)")
	rootCmd.PersistentFlags().StringVar(&modelName, "model", "", "Model name override")
	rootCmd.PersistentFlags().StringVar(&providerKey, "api-key", "", "API key override for judge provider")
	rootCmd.PersistentFlags().StringVar(&providerURL, "api-url", "", "Custom base URL for judge provider (e.g. Ollama or vLLM endpoint)")
	rootCmd.PersistentFlags().StringVar(&approvalMode, "approval", "auto", "Human approval channel for gray-zone calls (auto, cli, web, deny)")

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

func runProxy(ctx context.Context, cmd *cobra.Command) error {
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

	js, err := resolveJudge(cfg, cmd)
	if err != nil {
		return fmt.Errorf("judge: %w", err)
	}
	if js != nil && js.Approval == "web" && serveAddr == "" {
		return fmt.Errorf("approval channel \"web\" requires the dashboard; pass --serve :8700 or set judge.approval to cli")
	}

	logPath := cfg.AuditLog
	if auditPath != "" {
		logPath = auditPath
	}

	var dash *web.Dashboard
	var httpSrv *http.Server
	if serveAddr != "" {
		dash = web.New()
		var err error
		httpSrv, _, err = startDashboard(dash, serveAddr)
		if err != nil {
			return err
		}
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

	if js != nil {
		j, err := createJudge(js)
		if err != nil {
			return err
		}
		g.Judge = j
		g.RouterCfg = js.Router
		g.JudgeTimeout = js.Timeout

		switch js.Approval {
		case "web":
			wa := judge.NewWebApprover(func(p judge.PendingApproval) {
				dash.Broadcast("approval_required", p)
				slog.Warn("tool call awaiting operator approval",
					"id", p.ID, "tool", p.Tool, "risk_score", p.Verdict.RiskScore)
			})
			dash.Approver = wa
			g.Approver = wa
		case "deny":
			g.Approver = judge.AutoDenyApprover{}
		default:
			g.Approver = judge.NewCLIApprover()
		}

		slog.Info("tier 1 risk classifier active",
			"provider", js.Provider,
			"model", js.Model,
			"approval", js.Approval,
			"block_at", js.Router.BlockThreshold,
			"review_at", js.Router.ReviewThreshold,
			"fail_open", js.Router.FailOpen)
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

// resolveJudge merges judge settings from the config file, flags, and the
// environment. It returns nil when Tier 1 is disabled, which is the default.
func resolveJudge(cfg *Config, cmd *cobra.Command) (*judgeSettings, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Judge.Provider))
	if flagChanged(cmd, "judge-provider") {
		provider = strings.ToLower(strings.TrimSpace(judgeProvider))
	}

	// "none"/"off" is an explicit way to disable Tier 1 from the config file.
	if provider == "none" || provider == "off" {
		return nil, nil
	}
	if !mockJudge && !withJudge && provider == "" {
		return nil, nil
	}
	if mockJudge {
		provider = "mock"
	}
	if provider == "" {
		provider = "anthropic"
	}

	switch provider {
	case "anthropic", "openai", "gemini", "ollama", "mock":
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: anthropic, openai, gemini, ollama, mock)", provider)
	}

	model := modelName
	if model == "" {
		model = cfg.Judge.Model
	}
	apiURL := providerURL
	if apiURL == "" {
		apiURL = cfg.Judge.APIURL
	}

	apiKey := providerKey
	if apiKey == "" {
		apiKey = os.Getenv(providerEnvKey(provider))
	}

	router := judge.DefaultRouterConfig()
	if cfg.Judge.BlockThreshold > 0 {
		router.BlockThreshold = cfg.Judge.BlockThreshold
	}
	if cfg.Judge.ReviewThreshold > 0 {
		router.ReviewThreshold = cfg.Judge.ReviewThreshold
	}
	if cfg.Judge.FailOpen != nil {
		router.FailOpen = *cfg.Judge.FailOpen
	}
	if len(cfg.Judge.HighRiskTools) > 0 {
		router.HighRiskTools = make(map[string]bool, len(cfg.Judge.HighRiskTools))
		for _, tool := range cfg.Judge.HighRiskTools {
			router.HighRiskTools[tool] = true
		}
	}
	if router.ReviewThreshold < 0 || router.ReviewThreshold >= router.BlockThreshold || router.BlockThreshold > 1 {
		return nil, fmt.Errorf("invalid thresholds: review=%.2f block=%.2f (need 0 <= review < block <= 1)",
			router.ReviewThreshold, router.BlockThreshold)
	}

	approval := strings.ToLower(strings.TrimSpace(approvalMode))
	if approval == "" || approval == "auto" {
		approval = strings.ToLower(strings.TrimSpace(cfg.Judge.Approval))
	}
	if approval == "" || approval == "auto" {
		if serveAddr != "" {
			approval = "web"
		} else {
			approval = "cli"
		}
	}
	switch approval {
	case "cli", "web", "deny":
	default:
		return nil, fmt.Errorf("unknown approval channel %q (supported: auto, cli, web, deny)", approval)
	}

	return &judgeSettings{
		Provider: provider,
		Model:    model,
		APIKey:   apiKey,
		APIURL:   apiURL,
		Approval: approval,
		Timeout:  cfg.Judge.Timeout,
		Router:   router,
	}, nil
}

// flagChanged reports whether a flag was explicitly set, whether it lives on
// the command itself, is inherited, or is a persistent flag on the root.
func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Changed
	}
	if f := cmd.InheritedFlags().Lookup(name); f != nil {
		return f.Changed
	}
	if f := cmd.Root().PersistentFlags().Lookup(name); f != nil {
		return f.Changed
	}
	return false
}

func providerEnvKey(provider string) string {
	switch provider {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	case "gemini":
		return "GEMINI_API_KEY"
	case "ollama":
		// Ollama is keyless; the variable is a base URL, handled separately.
		return ""
	default:
		return ""
	}
}

func createJudge(s *judgeSettings) (judge.Judge, error) {
	switch s.Provider {
	case "mock":
		return judge.NewDeterministicMockJudge(), nil
	case "anthropic":
		if s.APIKey == "" {
			return nil, fmt.Errorf("anthropic judge requires ANTHROPIC_API_KEY (or --api-key, or use --mock-judge)")
		}
		return judge.NewAnthropicJudge(s.APIKey, s.Model), nil
	case "openai":
		if s.APIKey == "" {
			return nil, fmt.Errorf("openai judge requires OPENAI_API_KEY (or --api-key)")
		}
		return judge.NewOpenAIJudge(s.APIKey, s.Model, s.APIURL), nil
	case "gemini":
		if s.APIKey == "" {
			return nil, fmt.Errorf("gemini judge requires GEMINI_API_KEY (or --api-key)")
		}
		return judge.NewGeminiJudge(s.APIKey, s.Model), nil
	case "ollama":
		url := s.APIURL
		if url == "" {
			url = os.Getenv("OLLAMA_HOST")
		}
		return judge.NewOllamaJudge(url, s.Model), nil
	default:
		return nil, fmt.Errorf("unknown judge provider: %s", s.Provider)
	}
}

func startDashboard(dash *web.Dashboard, addr string) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", addr)
	actualAddr := addr
	if err != nil {
		// If default port is busy, automatically scan up to next free port
		if addr == ":8700" || addr == "localhost:8700" {
			for p := 8701; p <= 8710; p++ {
				nextAddr := fmt.Sprintf(":%d", p)
				ln, err = net.Listen("tcp", nextAddr)
				if err == nil {
					actualAddr = nextAddr
					break
				}
			}
		}
		if ln == nil {
			return nil, "", fmt.Errorf("port %s is already in use: %w", addr, err)
		}
	}

	srv := &http.Server{Handler: dash.Handler()}
	hostPort := actualAddr
	if strings.HasPrefix(hostPort, ":") {
		hostPort = "localhost" + hostPort
	}
	slog.Info("AgentGate Decision Cockpit running",
		"dashboard_url", fmt.Sprintf("http://%s/dashboard", hostPort),
		"landing_url", fmt.Sprintf("http://%s/", hostPort))

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("dashboard server error", "err", err)
		}
	}()
	return srv, actualAddr, nil
}

func runWatcher(ctx context.Context, addr, auditLogPath string, demo bool) error {
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

	srv, _, err := startDashboard(dash, addr)
	if err != nil {
		return err
	}
	<-ctx.Done()
	_ = srv.Close()
	slog.Info("dashboard exiting")
	return nil
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

// normalizeLegacyFlags converts single-dash long flags (like `-serve :8700` or `-demo`)
// into standard double-dash flags (`--serve :8700`, `--demo`) for seamless compatibility
// with Render deploy scripts, standard Go flag syntax, and POSIX style.
func normalizeLegacyFlags(args []string) []string {
	if len(args) <= 1 {
		return args
	}
	out := make([]string, len(args))
	out[0] = args[0]
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			name := arg[1:]
			if eqIdx := strings.Index(name, "="); eqIdx != -1 {
				flagName := name[:eqIdx]
				if len(flagName) > 1 {
					out[i] = "--" + name
					continue
				}
			} else if len(name) > 1 {
				out[i] = "--" + name
				continue
			}
		}
		out[i] = arg
	}
	return out
}

// Execute is the main entrypoint for the AgentGate CLI.
func Execute() {
	os.Args = normalizeLegacyFlags(os.Args)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
