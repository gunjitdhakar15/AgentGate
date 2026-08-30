// Package judge implements Tier 1 of AgentGate: a semantic risk classifier
// that runs on tool calls AFTER they clear Tier 0 (deny-by-default rules +
// regex argument guards).
//
// Tier 0 answers "does this call match a pattern I wrote down in advance?"
// Tier 1 answers "does this call look dangerous given what it actually
// does?" — which is the question regex can't answer for calls whose danger
// is in intent or effect rather than in any fixed substring (see
// eval/cases.json's semantic_gap category).
package judge

import "context"

// ToolCallContext is everything the judge is given to assess one call.
type ToolCallContext struct {
	Tool string
	// Arguments is the raw argument map, same as what Tier 0 sees.
	Arguments map[string]any
	// TaskContext is a short description of what the agent is trying to
	// accomplish overall, if the caller has one available. Optional —
	// an empty string is a valid input and the judge falls back to
	// judging the call in isolation.
	TaskContext string
	// RecentHistory is a short rolling window of prior tool calls in this
	// session (most recent last), used to catch escalation patterns that
	// look harmless one call at a time. See eval/cases.json's
	// escalation_step category.
	RecentHistory []string
}

// Category is a coarse label for why a call was flagged, used for
// reporting and audit — not for routing (RiskScore drives routing).
type Category string

const (
	CategorySafe                 Category = "safe"
	CategorySuspicious           Category = "suspicious"
	CategoryDestructive          Category = "destructive"
	CategoryExfiltration         Category = "exfiltration"
	CategoryPersistence          Category = "persistence"
	CategoryPrivilegeEscalation  Category = "privilege_escalation"
	CategoryOther                Category = "other"
)

// Verdict is the judge's structured assessment of one tool call.
type Verdict struct {
	// RiskScore is 0.0 (certainly safe) to 1.0 (certainly catastrophic).
	RiskScore float64
	Category  Category
	// Rationale is a short, human-readable explanation — this is what gets
	// shown to the human reviewer at the approval checkpoint, and what gets
	// written to the audit log either way.
	Rationale string
}

// Judge assesses a tool call's risk. Implementations must be safe for
// concurrent use.
type Judge interface {
	Assess(ctx context.Context, tc ToolCallContext) (Verdict, error)
}
