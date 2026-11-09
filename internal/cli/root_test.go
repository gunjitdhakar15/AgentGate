package cli

import (
	"reflect"
	"testing"
)

func TestNormalizeLegacyFlags(t *testing.T) {
	in := []string{"agentgate", "-serve", ":8700", "-demo", "-audit=test.log", "-v"}
	expected := []string{"agentgate", "--serve", ":8700", "--demo", "--audit=test.log", "-v"}

	out := normalizeLegacyFlags(in)
	if !reflect.DeepEqual(out, expected) {
		t.Fatalf("expected %+v, got %+v", expected, out)
	}
}

// resetJudgeFlags clears the package-level flag values so resolveJudge tests
// are independent of each other and of the real command line.
func resetJudgeFlags(t *testing.T) {
	t.Helper()
	prevWith, prevMock := withJudge, mockJudge
	prevProvider, prevModel := judgeProvider, modelName
	prevKey, prevURL, prevApproval := providerKey, providerURL, approvalMode
	prevServe := serveAddr

	withJudge, mockJudge = false, false
	judgeProvider, modelName = "", ""
	providerKey, providerURL, approvalMode = "", "", "auto"
	serveAddr = ""

	t.Cleanup(func() {
		withJudge, mockJudge = prevWith, prevMock
		judgeProvider, modelName = prevProvider, prevModel
		providerKey, providerURL, approvalMode = prevKey, prevURL, prevApproval
		serveAddr = prevServe
	})
}

func boolPtr(b bool) *bool { return &b }

func TestResolveJudgeDisabledByDefault(t *testing.T) {
	resetJudgeFlags(t)

	js, err := resolveJudge(&Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if js != nil {
		t.Fatalf("expected tier 1 disabled, got %+v", js)
	}
}

func TestResolveJudgeFromConfig(t *testing.T) {
	resetJudgeFlags(t)

	cfg := &Config{Judge: JudgeConfig{
		Provider:        "openai",
		Model:           "gpt-4o-mini",
		BlockThreshold:  0.9,
		ReviewThreshold: 0.5,
		FailOpen:        boolPtr(false),
		HighRiskTools:   []string{"shell", "sql_exec"},
		Timeout:         5,
	}}

	js, err := resolveJudge(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if js == nil {
		t.Fatal("expected tier 1 enabled from config")
	}
	if js.Provider != "openai" || js.Model != "gpt-4o-mini" {
		t.Errorf("unexpected provider/model: %+v", js)
	}
	if js.Router.BlockThreshold != 0.9 || js.Router.ReviewThreshold != 0.5 {
		t.Errorf("thresholds not applied: %+v", js.Router)
	}
	if js.Router.FailOpen {
		t.Error("explicit fail_open: false was ignored")
	}
	if !js.Router.HighRiskTools["sql_exec"] {
		t.Errorf("high_risk_tools not applied: %+v", js.Router.HighRiskTools)
	}
	if js.Approval != "cli" {
		t.Errorf("expected cli approval without dashboard, got %q", js.Approval)
	}
}

func TestResolveJudgeAutoApprovalUsesWebWithDashboard(t *testing.T) {
	resetJudgeFlags(t)
	serveAddr = ":8700"

	js, err := resolveJudge(&Config{Judge: JudgeConfig{Provider: "mock"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if js.Approval != "web" {
		t.Errorf("expected web approval when serving dashboard, got %q", js.Approval)
	}
}

func TestResolveJudgeMockFlagOverridesProvider(t *testing.T) {
	resetJudgeFlags(t)
	mockJudge = true

	js, err := resolveJudge(&Config{Judge: JudgeConfig{Provider: "anthropic"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if js == nil || js.Provider != "mock" {
		t.Fatalf("expected mock provider, got %+v", js)
	}
}

func TestResolveJudgeDisabledExplicitly(t *testing.T) {
	resetJudgeFlags(t)

	js, err := resolveJudge(&Config{Judge: JudgeConfig{Provider: "none"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if js != nil {
		t.Fatalf("expected provider none to disable tier 1, got %+v", js)
	}
}

func TestResolveJudgeRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "unknown provider",
			cfg:  &Config{Judge: JudgeConfig{Provider: "skynet"}},
		},
		{
			name: "review not below block",
			cfg: &Config{Judge: JudgeConfig{
				Provider:        "mock",
				BlockThreshold:  0.5,
				ReviewThreshold: 0.9,
			}},
		},
		{
			name: "threshold above one",
			cfg: &Config{Judge: JudgeConfig{
				Provider:       "mock",
				BlockThreshold: 1.5,
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetJudgeFlags(t)
			if _, err := resolveJudge(tc.cfg, nil); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
