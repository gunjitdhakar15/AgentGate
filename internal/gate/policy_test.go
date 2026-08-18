package gate

import (
	"encoding/json"
	"testing"
	"time"
)

func policyFromRules(rules []ToolRule, redact []RedactRule, limits []RateLimit) *compiledPolicy {
	cp, err := compilePolicy(Policy{ToolRules: rules, Redact: redact, RateLimits: limits})
	if err != nil {
		panic(err)
	}
	return cp
}

func args(kv ...string) map[string]any {
	m := make(map[string]any)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestDenyAllByDefault(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "*", Deny: true, Reason: "deny all"},
		{ApplyTo: "read_file", Allow: true},
	}, nil, nil)

	if d, _ := cp.Check("read_file", nil); !d.Allowed {
		t.Fatal("read_file should be allowed by explicit Allow")
	}
	if d, _ := cp.Check("shell", nil); d.Allowed {
		t.Fatalf("shell should be denied, got reason %q", d.Reason)
	}
}

func TestArgDenyPattern(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "shell", Allow: true, ArgDenyPattern: `(rm -rf|del /s)`, Reason: "dangerous"},
	}, nil, nil)

	if d, _ := cp.Check("shell", args("cmd", "rm -rf /")); d.Allowed {
		t.Fatal("rm -rf must be blocked")
	}
	if d, _ := cp.Check("shell", args("cmd", "ls -la")); !d.Allowed {
		t.Fatal("harmless command must pass")
	}
}

func TestAllowOverridesDeny(t *testing.T) {
	cp := policyFromRules([]ToolRule{
		{ApplyTo: "*", Deny: true},
		{ApplyTo: "git", Allow: true},
	}, nil, nil)

	if d, _ := cp.Check("git", nil); !d.Allowed {
		t.Fatal("allow should override deny")
	}
}

func TestKeyRestrictedRedaction(t *testing.T) {
	cp := policyFromRules(nil, []RedactRule{
		{Keys: []string{"api_key", "token"}, Pattern: ".*", Replacement: "***"},
		{Pattern: `sk-[A-Za-z0-9]{10,}`, Replacement: "***"},
	}, nil)

	dec, red := cp.Check("any", args("api_key", "super-secret", "path", "/tmp/x", "prompt", "my key is sk-1234567890abcdef"))
	if !dec.Allowed {
		t.Fatal("no deny expected here")
	}
	if red["api_key"] != "***" {
		t.Fatalf("api_key not redacted: %v", red["api_key"])
	}
	if red["path"] != "/tmp/x" {
		t.Fatalf("path must be untouched, got %v", red["path"])
	}
	if got := red["prompt"]; got != "my key is ***" {
		t.Fatalf("pattern redaction failed: %v", got)
	}
}

func TestNestedRedaction(t *testing.T) {
	cp := policyFromRules(nil, []RedactRule{
		{Keys: []string{"password"}, Pattern: ".*", Replacement: "***"},
	}, nil)

	orig := map[string]any{
		"config": map[string]any{
			"db": map[string]any{"password": "hunter2"},
		},
	}
	dec, red := cp.Check("any", orig)
	if !dec.Allowed {
		t.Fatal("no deny expected")
	}
	cfg := red["config"].(map[string]any)
	db := cfg["db"].(map[string]any)
	if db["password"] != "***" {
		t.Fatalf("nested password not redacted: %v", db["password"])
	}
}

func TestRedactTextResponse(t *testing.T) {
	cp := policyFromRules(nil, []RedactRule{
		{Pattern: `Bearer\s+[A-Za-z0-9._-]{10,}`},
	}, nil)
	out := cp.RedactText(`Authorization: Bearer abc123.def456 token`)
	if out != "Authorization: *** token" {
		t.Fatalf("response redaction failed: %q", out)
	}
}

func TestBadPatternsRejected(t *testing.T) {
	if _, err := compilePolicy(Policy{ToolRules: []ToolRule{
		{ApplyTo: "x", ArgDenyPattern: "("},
	}}); err == nil {
		t.Fatal("malformed regex must fail compile")
	}
	if _, err := compilePolicy(Policy{Redact: []RedactRule{{Pattern: "["}}}); err == nil {
		t.Fatal("malformed redact regex must fail compile")
	}
}

func TestMaxArgBytes(t *testing.T) {
	cp, err := compilePolicy(Policy{MaxArgBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := cp.Check("t", args("payload", "aaaaaaaaaaaaaaaaaaaa")); d.Allowed {
		t.Fatal("oversized args must be rejected")
	}
	if d, _ := cp.Check("t", args("a", "b")); !d.Allowed {
		t.Fatal("small args must pass")
	}
}

func TestRateLimiter(t *testing.T) {
	b := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !b.Allow("shell") {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	if b.Allow("shell") {
		t.Fatal("4th call in window must be denied")
	}
	if !b.Allow("other_tool") {
		t.Fatal("different key must have its own bucket")
	}
}

func TestRedactPayloadRoundTrip(t *testing.T) {
	cp := policyFromRules(nil, []RedactRule{
		{Keys: []string{"secret"}, Pattern: ".*", Replacement: "***"},
	}, nil)
	g := New(cp, nil, nil)
	body := []byte(`{"content":[{"type":"text","text":"ok"}],"secret":"ssshh"}`)
	out := g.RedactPayload(body)
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("payload must stay valid JSON: %v", err)
	}
	if decoded["secret"] != "***" {
		t.Fatalf("response secret not redacted: %v", decoded["secret"])
	}
}
