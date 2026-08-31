// Command eval-harness runs the adversarial case set in eval/cases.json
// against a compiled AgentGate policy and reports how many cases the policy
// got right, broken down by category.
//
// This is the "simple baseline" measurement tool referenced in the
// hackathon's Improvement Changelog: run it once against Tier 0 alone, then
// again after each new tier is added, and diff the results.
//
// Usage:
//
//	go run ./cmd/eval-harness -config configs/agentgate.yaml -cases eval/cases.json -out eval/results_tier0_baseline.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/gate"
	"github.com/gunjitdhakar15/AgentGate/internal/judge"
	"gopkg.in/yaml.v3"
)

// gateConfig mirrors the subset of cmd/agentgate's Config needed to compile
// a policy (tool_server / audit_log / timeout are irrelevant to eval).
type gateConfig struct {
	Policy gate.Policy `yaml:"policy"`
}

// evalCase is one adversarial test case.
type evalCase struct {
	ID            string         `json:"id"`
	Category      string         `json:"category"`
	Tool          string         `json:"tool"`
	Arguments     map[string]any `json:"arguments"`
	ExpectedIdeal string         `json:"expected_ideal"` // "allow" | "block"
	Notes         string         `json:"notes"`
}

type caseFile struct {
	Description string     `json:"description"`
	Cases       []evalCase `json:"cases"`
}

// caseResult is the per-case outcome, written to the results file so every
// score in the changelog table can be traced back to a specific case.
type caseResult struct {
	ID        string  `json:"id"`
	Category  string  `json:"category"`
	Tool      string  `json:"tool"`
	Expected  string  `json:"expected"`
	Actual    string  `json:"actual"`
	Correct   bool    `json:"correct"`
	Reason    string  `json:"reason,omitempty"`
	Rule      string  `json:"rule,omitempty"`
	Tier      string  `json:"tier"`                 // "tier0" or "tier0+tier1"
	RiskScore float64 `json:"risk_score,omitempty"`  // only set when judge ran
	Route     string  `json:"route,omitempty"`       // only set when judge ran
	JudgeErr  string  `json:"judge_error,omitempty"`
}

type categorySummary struct {
	Category string `json:"category"`
	Total    int    `json:"total"`
	Correct  int    `json:"correct"`
	Accuracy string `json:"accuracy"`
}

type report struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	PolicyLabel   string            `json:"policy_label"`
	TotalCases    int               `json:"total_cases"`
	ScoredCases   int               `json:"scored_cases"` // excludes escalation_step, scored separately
	TotalCorrect  int               `json:"total_correct"`
	OverallAcc    string            `json:"overall_accuracy"`
	ByCategory    []categorySummary `json:"by_category"`
	FalsePositive string            `json:"false_positive_rate"` // safe cases wrongly blocked
	MissedDanger  string            `json:"missed_danger_rate"`  // dangerous cases wrongly allowed
	Results       []caseResult      `json:"results"`
}

func main() {
	var (
		configPath = flag.String("config", "configs/agentgate.yaml", "policy config to evaluate")
		casesPath  = flag.String("cases", "eval/cases.json", "adversarial case set")
		outPath    = flag.String("out", "", "write full JSON report here (optional)")
		label      = flag.String("label", "tier0-baseline", "label for this run, e.g. tier0-baseline, tier0+tier1")
		withJudge  = flag.Bool("with-judge", false, "also run Tier 1 (LLM judge) on calls Tier 0 allows; requires ANTHROPIC_API_KEY")
		mockJudge  = flag.Bool("mock-judge", false, "run Tier 1 evaluation using offline deterministic simulator (no API key required)")
		model      = flag.String("model", "", "override judge model (default: claude-haiku-4-5-20251001)")
	)
	flag.Parse()

	var j judge.Judge
	routerCfg := judge.DefaultRouterConfig()
	if *mockJudge {
		j = judge.NewDeterministicMockJudge()
		*withJudge = true
	} else if *withJudge {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			fatalf("-with-judge requires ANTHROPIC_API_KEY to be set (or use -mock-judge for offline evaluation)")
		}
		j = judge.NewAnthropicJudge(apiKey, *model)
	}

	cfgBytes, err := os.ReadFile(*configPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	var cfg gateConfig
	if err := yaml.Unmarshal(cfgBytes, &cfg); err != nil {
		fatalf("parse config: %v", err)
	}
	cp, err := gate.Compile(cfg.Policy)
	if err != nil {
		fatalf("compile policy: %v", err)
	}

	casesBytes, err := os.ReadFile(*casesPath)
	if err != nil {
		fatalf("read cases: %v", err)
	}
	var cf caseFile
	if err := json.Unmarshal(casesBytes, &cf); err != nil {
		fatalf("parse cases: %v", err)
	}

	var (
		results        []caseResult
		byCat          = map[string]*categorySummary{}
		scored         int
		correct        int
		safeTotal      int
		safeBlocked    int // false positives
		dangerTotal    int
		dangerAllowed  int // missed danger
	)

	ctx := context.Background()
	tierLabel := "tier0"
	if *withJudge {
		tierLabel = "tier0+tier1"
	}

	for _, c := range cf.Cases {
		dec, redacted := cp.Check(c.Tool, c.Arguments)
		actual := "allow"
		if !dec.Allowed {
			actual = "block"
		}

		cr := caseResult{Tier: tierLabel, Rule: dec.Rule}

		// Tier 1 only runs on calls Tier 0 already allowed — same wiring
		// as the live gate in internal/gate/gate.go.
		if *withJudge && dec.Allowed {
			verdict, jerr := j.Assess(ctx, judge.ToolCallContext{
				Tool: c.Tool, Arguments: redacted,
			})
			var route judge.Route
			if jerr != nil {
				route = judge.RouteOnError(routerCfg, c.Tool)
				cr.JudgeErr = jerr.Error()
			} else {
				route = judge.RouteVerdict(routerCfg, verdict)
				cr.RiskScore = verdict.RiskScore
			}
			cr.Route = string(route)
			// RouteBlock and RouteNeedsApproval both mean the call does
			// NOT execute silently — score both as "block" here since the
			// eval cases only label allow/block, not the three-way route.
			if route != judge.RouteAllow {
				actual = "block"
			}
		}

		cs, ok := byCat[c.Category]
		if !ok {
			cs = &categorySummary{Category: c.Category}
			byCat[c.Category] = cs
		}

		// escalation_step cases exist for Tier 2 (session-history) evaluation
		// and are not individually scoreable against a stateless Tier 0/1
		// policy — they're included in the report for visibility but
		// excluded from the accuracy denominator.
		isScored := c.Category != "escalation_step"

		correctCall := actual == c.ExpectedIdeal
		if isScored {
			scored++
			cs.Total++
			if correctCall {
				correct++
				cs.Correct++
			}
			if c.ExpectedIdeal == "allow" {
				safeTotal++
				if actual == "block" {
					safeBlocked++
				}
			} else {
				dangerTotal++
				if actual == "allow" {
					dangerAllowed++
				}
			}
		}

		cr.ID, cr.Category, cr.Tool = c.ID, c.Category, c.Tool
		cr.Expected, cr.Actual, cr.Correct = c.ExpectedIdeal, actual, correctCall
		cr.Reason = dec.Reason
		results = append(results, cr)
	}

	var catSummaries []categorySummary
	for _, cs := range byCat {
		cs.Accuracy = pct(cs.Correct, cs.Total)
		catSummaries = append(catSummaries, *cs)
	}
	sort.Slice(catSummaries, func(i, j int) bool { return catSummaries[i].Category < catSummaries[j].Category })

	rep := report{
		GeneratedAt:   time.Now().UTC(),
		PolicyLabel:   *label,
		TotalCases:    len(cf.Cases),
		ScoredCases:   scored,
		TotalCorrect:  correct,
		OverallAcc:    pct(correct, scored),
		ByCategory:    catSummaries,
		FalsePositive: pct(safeBlocked, safeTotal),
		MissedDanger:  pct(dangerAllowed, dangerTotal),
		Results:       results,
	}

	printReport(rep)

	if *outPath != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*outPath, b, 0o644); err != nil {
			fatalf("write report: %v", err)
		}
		fmt.Printf("\nfull report written to %s\n", *outPath)
	}
}

func printReport(r report) {
	fmt.Printf("=== AgentGate eval report: %s ===\n", r.PolicyLabel)
	fmt.Printf("scored cases: %d   correct: %d   overall accuracy: %s\n", r.ScoredCases, r.TotalCorrect, r.OverallAcc)
	fmt.Printf("false positive rate (safe calls wrongly blocked): %s\n", r.FalsePositive)
	fmt.Printf("missed danger rate  (dangerous calls wrongly allowed): %s\n\n", r.MissedDanger)
	fmt.Printf("%-16s %6s %8s %10s\n", "category", "total", "correct", "accuracy")
	for _, cs := range r.ByCategory {
		fmt.Printf("%-16s %6d %8d %10s\n", cs.Category, cs.Total, cs.Correct, cs.Accuracy)
	}
	fmt.Println()
	for _, res := range r.Results {
		mark := "OK  "
		if !res.Correct {
			mark = "MISS"
		}
		fmt.Printf("[%s] %-20s tool=%-14s expected=%-6s actual=%-6s cat=%s\n",
			mark, res.ID, res.Tool, res.Expected, res.Actual, res.Category)
	}
}

func pct(n, total int) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "eval-harness: "+format+"\n", args...)
	os.Exit(1)
}
