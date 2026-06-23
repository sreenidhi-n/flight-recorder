// Package contract implements tass.contract.yaml loading and enforcement.
// A contract defines what capabilities a service is allowed to have.
// Violations are hard blocks — they cannot be resolved via confirm/revert;
// only by editing tass.contract.yaml itself.
package contract

import (
	"fmt"
	"path"
	"strings"

	"github.com/tass-security/tass/pkg/contracts"
	"gopkg.in/yaml.v3"
)

// matchGlob matches pattern against text where '*' matches any sequence of
// characters, including ':' (unlike path.Match which treats '/' specially).
// Use this for capability ID patterns like "boto3:*" or "net/http:client:*".
// path.Match is still used for patterns that contain '/' and are clearly
// URL hostname patterns — for those, '*' should not cross '/' boundaries.
func matchGlob(pattern, text string) bool {
	// Fast path: no wildcard.
	if !strings.Contains(pattern, "*") {
		return pattern == text
	}
	// If the pattern contains '/' but not ':', delegate to path.Match which
	// has correct slash-aware semantics for URL hostname glob matching.
	if strings.Contains(pattern, "/") && !strings.Contains(pattern, ":") {
		matched, _ := path.Match(pattern, text)
		return matched
	}
	// Hand-rolled glob: '*' matches any sequence (including ':' and '/').
	// Implements the classic DP-based wildcard match iteratively.
	p, t := []rune(pattern), []rune(text)
	pi, ti := 0, 0
	starIdx, match := -1, 0
	for ti < len(t) {
		if pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]) {
			pi++
			ti++
		} else if pi < len(p) && p[pi] == '*' {
			starIdx = pi
			match = ti
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			match++
			ti = match
		} else {
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Contract is the parsed tass.contract.yaml at a repo root.
type Contract struct {
	Version   int                 `yaml:"version"`
	Service   string              `yaml:"service"`
	Allowed   map[string][]string `yaml:"allowed"`   // category → allowed endpoint patterns
	Forbidden map[string][]string `yaml:"forbidden"` // category → patterns ("*" = all)
	Limits    map[string]int      `yaml:"limits"`    // category → max count of novel caps
}

// ViolationRule identifies which contract rule was broken.
type ViolationRule string

const (
	RuleForbidden    ViolationRule = "forbidden"
	RuleNotInAllowed ViolationRule = "not_in_allowed"
	RuleLimitExceeded ViolationRule = "limit_exceeded"
)

// Violation is one contract breach found during a scan.
// For limit_exceeded violations, Capability is zero-value (the limit applies
// to the whole category, not a single capability).
type Violation struct {
	Capability contracts.Capability
	Rule       ViolationRule
	Reason     string
}

// Load parses a tass.contract.yaml file.
// Returns (nil, nil) for empty input — callers should treat nil contract as no-op.
func Load(data []byte) (*Contract, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var c Contract
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse tass.contract.yaml: %w", err)
	}
	return &c, nil
}

// Check evaluates all capabilities against the contract rules and returns
// any violations. Does not modify the input slice.
//
// Rule evaluation order:
//  1. forbidden — if category is in Forbidden and the capability matches any pattern → violation
//  2. not_in_allowed — if category is in Allowed and the capability matches no allowed pattern → violation
//  3. limit_exceeded — if novel count for a category exceeds its limit → violation
func (c *Contract) Check(caps []contracts.Capability) []Violation {
	if c == nil {
		return nil
	}
	var violations []Violation
	catCount := make(map[string]int, len(caps))

	for _, cap := range caps {
		cat := string(cap.Category)
		catCount[cat]++

		// Rule 1: forbidden
		if patterns, ok := c.Forbidden[cat]; ok && matchesAny(cap, patterns) {
			violations = append(violations, Violation{
				Capability: cap,
				Rule:       RuleForbidden,
				Reason:     fmt.Sprintf("category %q is forbidden by contract (matched forbidden rule)", cat),
			})
			continue // no point checking allowed if already forbidden
		}

		// Rule 2: not_in_allowed
		if patterns, ok := c.Allowed[cat]; ok && !matchesAny(cap, patterns) {
			violations = append(violations, Violation{
				Capability: cap,
				Rule:       RuleNotInAllowed,
				Reason:     fmt.Sprintf("capability %q is not in the allowed list for category %q", cap.Name, cat),
			})
		}
	}

	// Rule 3: limit_exceeded (category-level, not per-capability)
	for cat, limit := range c.Limits {
		if count := catCount[cat]; count > limit {
			violations = append(violations, Violation{
				Rule:   RuleLimitExceeded,
				Reason: fmt.Sprintf("category %q has %d novel capabilities, contract limit is %d", cat, count, limit),
			})
		}
	}

	return violations
}

// ViolatedIDs returns a set of capability IDs that have individual violations
// (forbidden or not_in_allowed). limit_exceeded violations are excluded since
// they apply to a category, not a specific capability.
func ViolatedIDs(violations []Violation) map[string]string {
	m := make(map[string]string)
	for _, v := range violations {
		if v.Rule == RuleForbidden || v.Rule == RuleNotInAllowed {
			m[v.Capability.ID] = v.Reason
		}
	}
	return m
}

// matchesAny returns true if the capability matches any of the given patterns.
// Pattern semantics:
//   - "*" matches everything
//   - glob patterns (path.Match syntax) matched against capability name, ID,
//     and each whitespace/punctuation token within the raw evidence
//   - substring match as a fallback
func matchesAny(cap contracts.Capability, patterns []string) bool {
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		pl := strings.ToLower(p)
		targets := []string{
			strings.ToLower(cap.Name),
			strings.ToLower(cap.ID),
			strings.ToLower(cap.RawEvidence),
		}
		for _, t := range targets {
			if t == "" {
				continue
			}
			// Glob match on full target string — uses matchGlob so '*' crosses ':'.
			if matchGlob(pl, t) {
				return true
			}
			// Glob match on individual tokens within the target — allows patterns
			// like "*.stripe.com" to match "api.stripe.com" inside a longer string
			// such as "http.Post(api.stripe.com/v1/charges)".
			for _, tok := range tokenize(t) {
				if matchGlob(pl, tok) {
					return true
				}
			}
			// Substring match — useful for simple endpoint names
			if strings.Contains(t, pl) {
				return true
			}
		}
	}
	return false
}

// tokenize splits s on common URL/code delimiters to extract meaningful tokens
// for glob matching.
func tokenize(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '/' || r == '(' || r == ')' || r == ':' || r == ' ' ||
			r == '"' || r == '\'' || r == ',' || r == ';'
	})
}
