package mitigation

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"unicode"

	"github.com/tass-security/tass/internal/contract"
	"github.com/tass-security/tass/pkg/contracts"
)

// MitigationContext carries the data fields referenced by every template.
// All fields are plain strings so templates remain side-effect free.
type MitigationContext struct {
	// CapabilityName is the human-readable name of the detected capability.
	CapabilityName string
	// CapabilityID is the full deterministic ID (e.g. "ast:go:net/http:Client.Do").
	CapabilityID string
	// Category is the category string (e.g. "network_access").
	Category string
	// Location is "file:line" of the primary detection point, or "" if unknown.
	Location string
	// Reason is the violation explanation from the contract check.
	Reason string
	// Rule is the contract rule that was broken (forbidden / not_in_allowed / limit_exceeded).
	Rule string
	// Slug is a URL-safe, K8s-name-safe slug derived from the capability ID.
	// Safe to embed in Kubernetes resource names and YAML comment fields.
	Slug string
}

// GenerateMitigation takes a single contract.Violation and returns a clean
// Markdown string containing a category-specific IaC/IAM snippet that can
// be posted directly into a GitHub PR comment.
//
// The output is deterministic: identical Violation inputs always produce
// identical output. No network calls, no side effects.
func GenerateMitigation(v contract.Violation) string {
	ctx := buildContext(v)

	var (
		snippet  string
		fence    string // markdown code-fence language tag
		heading  string
	)

	switch v.Capability.Category {
	case contracts.CatNetworkAccess:
		snippet = render(templates.NetworkPolicy, ctx)
		fence = "yaml"
		heading = "Kubernetes NetworkPolicy — restrict egress"

	case contracts.CatExternalAPI:
		snippet = render(templates.IAMPolicy, ctx)
		fence = "json"
		heading = "AWS IAM Policy — least-privilege external API access"

	case contracts.CatDatabaseOp:
		snippet = render(templates.SQLGrant, ctx)
		fence = "sql"
		heading = "SQL Grant — least-privilege database access"

	case contracts.CatFileSystem:
		snippet = render(templates.ReadOnlyFS, ctx)
		fence = "yaml"
		heading = "Kubernetes securityContext — read-only root filesystem"

	case contracts.CatPrivilege:
		snippet = render(templates.DropCaps, ctx)
		fence = "yaml"
		heading = "Kubernetes securityContext — drop ALL Linux capabilities"

	default:
		// CatExternalDep or any future category: emit a generic advisory.
		return buildGenericMitigation(ctx)
	}

	return buildMarkdown(ctx, heading, fence, snippet)
}

// buildContext extracts all template-data fields from a Violation.
func buildContext(v contract.Violation) MitigationContext {
	cap := v.Capability

	name := cap.Name
	if name == "" {
		name = cap.ID
	}
	if name == "" {
		name = "(unknown capability)"
	}

	loc := cap.Location.File
	if cap.Location.Line > 0 && loc != "" {
		loc = fmt.Sprintf("%s:%d", loc, cap.Location.Line)
	}

	return MitigationContext{
		CapabilityName: name,
		CapabilityID:   cap.ID,
		Category:       string(cap.Category),
		Location:       loc,
		Reason:         v.Reason,
		Rule:           string(v.Rule),
		Slug:           slugify(cap.ID),
	}
}

// render executes tmpl against ctx and returns the rendered string.
// Panics only if the template itself is malformed (caught at init time).
func render(tmpl *template.Template, ctx MitigationContext) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		// Should never happen: templates are parsed at init and MitigationContext
		// fields are always present (zero-value strings are valid).
		return fmt.Sprintf("<!-- template error: %v -->", err)
	}
	return buf.String()
}

// buildMarkdown wraps a generated IaC snippet in clean Markdown suitable for
// a GitHub PR comment or review body.
func buildMarkdown(ctx MitigationContext, heading, fence, snippet string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "#### Suggested Mitigation: %s\n\n", heading)
	fmt.Fprintf(&b, "| Field | Value |\n")
	fmt.Fprintf(&b, "|-------|-------|\n")
	fmt.Fprintf(&b, "| **Capability** | `%s` |\n", ctx.CapabilityName)
	if ctx.CapabilityID != "" {
		fmt.Fprintf(&b, "| **ID** | `%s` |\n", ctx.CapabilityID)
	}
	if ctx.Location != "" {
		fmt.Fprintf(&b, "| **Detected at** | `%s` |\n", ctx.Location)
	}
	fmt.Fprintf(&b, "| **Contract rule** | `%s` |\n", ctx.Rule)
	if ctx.Reason != "" {
		fmt.Fprintf(&b, "| **Reason** | %s |\n", ctx.Reason)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "```%s\n", fence)
	fmt.Fprintf(&b, "%s\n", snippet)
	fmt.Fprintf(&b, "```\n\n")

	fmt.Fprintf(&b, "> ⚠️ This snippet is a generated starting point. Review and adapt it for your specific infrastructure before applying.\n")

	return b.String()
}

// buildGenericMitigation returns an advisory for categories that have no
// specific IaC template (e.g. CatExternalDep or future categories).
func buildGenericMitigation(ctx MitigationContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#### Suggested Mitigation: review added capability\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n")
	fmt.Fprintf(&b, "|-------|-------|\n")
	fmt.Fprintf(&b, "| **Capability** | `%s` |\n", ctx.CapabilityName)
	if ctx.CapabilityID != "" {
		fmt.Fprintf(&b, "| **ID** | `%s` |\n", ctx.CapabilityID)
	}
	if ctx.Location != "" {
		fmt.Fprintf(&b, "| **Detected at** | `%s` |\n", ctx.Location)
	}
	fmt.Fprintf(&b, "| **Contract rule** | `%s` |\n", ctx.Rule)
	if ctx.Reason != "" {
		fmt.Fprintf(&b, "| **Reason** | %s |\n", ctx.Reason)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b,
		"No IaC template is defined for category `%s`. "+
			"Review the capability manually and update `tass.contract.yaml` "+
			"with an explicit `allowed` or `forbidden` rule to prevent future drift.\n",
		ctx.Category,
	)
	return b.String()
}

// slugify converts a capability ID into a string that is safe to use as a
// Kubernetes resource name component (lowercase alphanumeric + hyphens, max 50 chars).
// Example: "ast:go:net/http:Client.Do" → "ast-go-net-http-client-do"
func slugify(s string) string {
	if s == "" {
		return "tass-mitigation"
	}
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			b.WriteRune('-')
			prevHyphen = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	// K8s names must be ≤ 63 chars for labels; cap at 50 to leave room for prefix.
	if len(slug) > 50 {
		slug = slug[:50]
		slug = strings.TrimRight(slug, "-")
	}
	if slug == "" {
		return "tass-mitigation"
	}
	return slug
}
