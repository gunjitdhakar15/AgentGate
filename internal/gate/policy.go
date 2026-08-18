package gate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Policy is the declarative firewall configuration applied to every
// tools/call routed through the gate.
type Policy struct {
	// ToolRules decide whether a tool call proceeds.
	ToolRules []ToolRule `yaml:"tool_rules" json:"tool_rules"`
	// Redaction rules scrub secrets from arguments and responses before the
	// agent or the audit log sees them.
	Redact []RedactRule `yaml:"redact" json:"redact"`
	// RateLimits cap how often each tool may be invoked.
	RateLimits []RateLimit `yaml:"rate_limits" json:"rate_limits"`
	// MaxArgBytes rejects tool calls whose serialized arguments exceed a size.
	MaxArgBytes int           `yaml:"max_arg_bytes" json:"max_arg_bytes"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
}

// ToolRule matches a tool by name or argument pattern.
type ToolRule struct {
	// ApplyTo selects the tool; empty means all tools.
	ApplyTo string `yaml:"apply_to" json:"apply_to"`
	// Allow whitelists the tool. If any Allow rule matches, the call passes
	// even if Deny rules exist; think of Allow as an override for broad Deny.
	Allow bool `yaml:"allow" json:"allow"`
	// Deny blacklists the tool. Deny wins unless an Allow rule matches.
	Deny bool `yaml:"deny" json:"deny"`
	// ArgDenyPattern rejects calls whose arguments match this regex.
	ArgDenyPattern string `yaml:"arg_deny_pattern,omitempty" json:"arg_deny_pattern,omitempty"`
	// Reason is recorded in the audit log when the rule fires.
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// RedactRule masks values matching a pattern inside arguments/responses.
type RedactRule struct {
	// Pattern is matched against string values; the match is replaced with
	// Replacement.
	Pattern string `yaml:"pattern" json:"pattern"`
	// Replacement defaults to "***".
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	// Keys (case-insensitive) restrict redaction to argument keys, e.g.
	// "api_key", "password". Empty means match the pattern anywhere.
	Keys []string `yaml:"keys,omitempty" json:"keys,omitempty"`
}

// RateLimit throttles calls for a tool (or all tools).
type RateLimit struct {
	ApplyTo string `yaml:"apply_to" json:"apply_to"` // empty = all tools
	// Burst is the maximum number of calls in a burst window.
	Burst int `yaml:"burst" json:"burst"`
	// Window is the reset period.
	Window time.Duration `yaml:"window" json:"window"`
}

// Decision is the outcome of a policy check.
type Decision struct {
	Allowed bool
	// Reason why the call was blocked, if any.
	Reason string
	// Tool is the resolved rule that fired (for telemetry).
	Rule string
}

// compiledPolicy pre-compiles regexes for hot-path use.
type compiledPolicy struct {
	p         Policy
	argDenies []struct {
		tool   string
		re     *regexp.Regexp
		reason string
	}
	redacts []redactRule
}

// compilePolicy validates and pre-compiles regex rules. It fails fast on
// malformed patterns so misconfiguration is caught at startup.
func compilePolicy(p Policy) (*compiledPolicy, error) {
	c := &compiledPolicy{p: p}
	for _, r := range p.ToolRules {
		if r.ArgDenyPattern != "" {
			re, err := regexp.Compile(r.ArgDenyPattern)
			if err != nil {
				return nil, fmt.Errorf("tool rule %q: bad pattern %q: %w", r.ApplyTo, r.ArgDenyPattern, err)
			}
			c.argDenies = append(c.argDenies, struct {
				tool   string
				re     *regexp.Regexp
				reason string
			}{tool: r.ApplyTo, re: re, reason: r.Reason})
		}
	}
	for _, r := range p.Redact {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("redact rule: bad pattern %q: %w", r.Pattern, err)
		}
		repl := r.Replacement
		if repl == "" {
			repl = "***"
		}
		keys := make(map[string]bool, len(r.Keys))
		for _, k := range r.Keys {
			keys[strings.ToLower(k)] = true
		}
		c.redacts = append(c.redacts, redactRule{
			re:     re,
			repl:   repl,
			keys:   keys,
			anyKey: len(keys) == 0,
		})
	}
	return c, nil
}

// Check evaluates the policy for a tool call. args is the raw argument map
// (or nil when arguments are absent). It returns a Decision plus a copy of
// arguments with redaction applied.
func (c *compiledPolicy) Check(tool string, args map[string]any) (Decision, map[string]any) {
	dec := Decision{Allowed: true, Rule: "default-allow"}

	// 1. Size guard.
	if c.p.MaxArgBytes > 0 {
		if b, err := json.Marshal(args); err == nil && len(b) > c.p.MaxArgBytes {
			dec.Allowed = false
			dec.Reason = fmt.Sprintf("arguments exceed %d bytes", c.p.MaxArgBytes)
			dec.Rule = "max_arg_bytes"
			return dec, args
		}
	}

	// 2. Tool rules: a Deny rule blocks unless an Allow rule for the same
	// tool overrides it (deny-by-default pattern).
	blocked := false
	blockReason := ""
	for _, r := range c.p.ToolRules {
		if r.ApplyTo != "" && !strings.EqualFold(r.ApplyTo, tool) && !strings.EqualFold(r.ApplyTo, "*") {
			continue
		}
		if r.Deny {
			blocked = true
			blockReason = r.Reason
			dec.Rule = "deny:" + tool
		}
		if r.Allow {
			blocked = false
			blockReason = ""
			dec.Rule = "allow:" + tool
		}
	}

	// 3. Argument pattern denials are a hard safety net: they block even
	// when the tool is allowed, and an Allow override cannot undo them.
	rb, _ := json.Marshal(args)
	argText := string(rb)
	for _, ad := range c.argDenies {
		if ad.tool != "" && !strings.EqualFold(ad.tool, tool) && !strings.EqualFold(ad.tool, "*") {
			continue
		}
		if ad.re.MatchString(argText) {
			blocked = true
			blockReason = ad.reason
			dec.Rule = "arg_deny:" + ad.re.String()
			break
		}
	}

	if blocked {
		dec.Allowed = false
		dec.Reason = orDefault(blockReason, "blocked by policy rule")
		return dec, args
	}

	// 4. Redact arguments in place (copy).
	redacted, _ := redactValue(args, c.redacts).(map[string]any)
	if redacted == nil {
		redacted = args
	}
	return dec, redacted
}

// RedactText applies redaction rules to a response payload, returning
// sanitized bytes.
func (c *compiledPolicy) RedactText(s string) string {
	for _, r := range c.redacts {
		if r.anyKey {
			s = r.re.ReplaceAllString(s, r.repl)
		}
	}
	return s
}

// redactRule is the compiled form of a RedactRule.
type redactRule = struct {
	re     *regexp.Regexp
	repl   string
	keys   map[string]bool
	anyKey bool
}

// redactValue walks a decoded JSON value and masks sensitive strings.
// active carries the rules in force for the current subtree: unrestricted
// rules plus any key-restricted rules whose key matched at an ancestor
// level. Key-restricted rules apply to the whole subtree under their key.
func redactValue(v any, all []redactRule) any {
	return redactValueActive(v, all, activeRulesForRoot(all))
}

// activeRulesForRoot seeds the active set with unrestricted rules only.
func activeRulesForRoot(all []redactRule) []redactRule {
	var out []redactRule
	for _, r := range all {
		if r.anyKey {
			out = append(out, r)
		}
	}
	return out
}

func redactValueActive(v any, all, active []redactRule) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = redactValueActive(val, all, activate(all, active, k))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValueActive(val, all, active)
		}
		return out
	case string:
		for _, r := range active {
			t = r.re.ReplaceAllString(t, r.repl)
		}
		return t
	default:
		return v
	}
}

// activate adds rules whose key matches k to the active set. Unrestricted
// rules are always active (handled by the root seed); nested maps keep the
// current active set for deeper keys.
func activate(all, active []redactRule, k string) []redactRule {
	lk := strings.ToLower(k)
	for _, r := range all {
		if !r.anyKey && r.keys[lk] && !containsRule(active, r) {
			active = append(active, r)
		}
	}
	return active
}

func containsRule(set []redactRule, r redactRule) bool {
	for _, s := range set {
		if s.re.String() == r.re.String() {
			return true
		}
	}
	return false
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
