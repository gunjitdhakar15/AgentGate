package judge

import "testing"

func TestRouteVerdict(t *testing.T) {
	cfg := DefaultRouterConfig()
	cases := []struct {
		name string
		risk float64
		want Route
	}{
		{"clearly safe", 0.05, RouteAllow},
		{"just under review threshold", 0.39, RouteAllow},
		{"at review threshold", 0.4, RouteNeedsApproval},
		{"mid review band", 0.6, RouteNeedsApproval},
		{"just under block threshold", 0.79, RouteNeedsApproval},
		{"at block threshold", 0.8, RouteBlock},
		{"maximum risk", 1.0, RouteBlock},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RouteVerdict(cfg, Verdict{RiskScore: c.risk})
			if got != c.want {
				t.Errorf("risk=%.2f: got %s, want %s", c.risk, got, c.want)
			}
		})
	}
}

func TestRouteOnError_HighRiskToolAlwaysFailsClosed(t *testing.T) {
	cfg := DefaultRouterConfig() // FailOpen: true, but shell is high-risk
	if got := RouteOnError(cfg, "shell"); got != RouteBlock {
		t.Errorf("high-risk tool with FailOpen=true: got %s, want %s (fail-closed override must win)", got, RouteBlock)
	}
	if got := RouteOnError(cfg, "write_file"); got != RouteBlock {
		t.Errorf("high-risk tool with FailOpen=true: got %s, want %s", got, RouteBlock)
	}
}

func TestRouteOnError_LowRiskToolRespectsFailOpen(t *testing.T) {
	cfg := DefaultRouterConfig() // FailOpen: true
	if got := RouteOnError(cfg, "read_file"); got != RouteAllow {
		t.Errorf("non-high-risk tool with FailOpen=true: got %s, want %s", got, RouteAllow)
	}
}

func TestRouteOnError_FailClosedConfig(t *testing.T) {
	cfg := DefaultRouterConfig()
	cfg.FailOpen = false
	if got := RouteOnError(cfg, "read_file"); got != RouteBlock {
		t.Errorf("FailOpen=false: got %s, want %s even for a non-high-risk tool", got, RouteBlock)
	}
}
