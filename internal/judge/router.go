package judge

// Route is the outcome of applying RouterConfig to a Verdict (or to a judge
// error, which is itself a routable outcome — see RouterConfig.HighRiskTools).
type Route string

const (
	RouteAllow         Route = "allow"
	RouteBlock         Route = "block"
	RouteNeedsApproval Route = "needs_approval"
)

// RouterConfig controls how a Verdict (or a judge failure) becomes a Route.
// This is deliberately separate from AnthropicJudge so the routing policy —
// the part a judge might actually be graded on in an interview — can be
// unit tested without a network call.
type RouterConfig struct {
	// BlockThreshold: risk_score at or above this is auto-blocked.
	BlockThreshold float64
	// ReviewThreshold: risk_score at or above this (and below
	// BlockThreshold) requires human approval before the call proceeds.
	// Below this, the call is auto-allowed.
	ReviewThreshold float64
	// FailOpen: if true, a judge error (timeout, API error, malformed
	// response) results in RouteAllow instead of RouteBlock — EXCEPT for
	// tools listed in HighRiskTools, which always fail closed regardless
	// of this setting. This split exists because pure fail-open on a
	// security firewall defeats deny-by-default for exactly the calls that
	// matter most; pure fail-closed makes a judge outage take down the
	// whole agent for even harmless reads.
	FailOpen bool
	// HighRiskTools always fail closed on judge error, irrespective of
	// FailOpen. Typically the tools capable of destructive or
	// irreversible effects (e.g. "shell", "write_file").
	HighRiskTools map[string]bool
}

// DefaultRouterConfig is a reasonable starting point: block at 0.8+,
// require approval from 0.4 to 0.8, fail open except for shell/write_file.
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		BlockThreshold:  0.8,
		ReviewThreshold: 0.4,
		FailOpen:        true,
		HighRiskTools:   map[string]bool{"shell": true, "write_file": true},
	}
}

// RouteVerdict maps a successful Verdict to a Route.
func RouteVerdict(cfg RouterConfig, v Verdict) Route {
	switch {
	case v.RiskScore >= cfg.BlockThreshold:
		return RouteBlock
	case v.RiskScore >= cfg.ReviewThreshold:
		return RouteNeedsApproval
	default:
		return RouteAllow
	}
}

// RouteOnError maps a judge failure (timeout, API error, ...) to a Route,
// honoring the FailOpen / HighRiskTools split documented on RouterConfig.
func RouteOnError(cfg RouterConfig, tool string) Route {
	if cfg.HighRiskTools[tool] {
		return RouteBlock
	}
	if cfg.FailOpen {
		return RouteAllow
	}
	return RouteBlock
}
