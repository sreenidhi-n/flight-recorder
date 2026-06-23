package github_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/contract"
	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/pkg/contracts"
)

func TestRenderComment_NoCapabilities(t *testing.T) {
	body := gh.RenderComment("scan-001", nil, nil, "http://localhost:8080")

	if !strings.Contains(body, "No New Capabilities") {
		t.Errorf("expected 'No New Capabilities' header, got:\n%s", body)
	}
	if !strings.Contains(body, "<!-- tass-scan-id:scan-001") {
		t.Errorf("missing marker in comment:\n%s", body)
	}
	// Should NOT contain the table header
	if strings.Contains(body, "| # |") {
		t.Errorf("zero-cap comment should not have capability table:\n%s", body)
	}
}

func TestRenderComment_WithCapabilities(t *testing.T) {
	caps := []contracts.Capability{
		{
			ID:       "dep:go:github.com/stripe/stripe-go/v76",
			Name:     "stripe-go",
			Category: contracts.CatExternalDep,
			Source:   contracts.LayerDependency,
			Location: contracts.CodeLocation{File: "go.mod", Line: 14},
		},
		{
			ID:       "ast:go:net/http:Client.Do",
			Name:     "HTTP client outbound request",
			Category: contracts.CatNetworkAccess,
			Source:   contracts.LayerAST,
			Location: contracts.CodeLocation{File: "internal/client/api.go", Line: 42},
		},
		{
			ID:       "ast:go:os:file:WriteFile",
			Name:     "os.WriteFile",
			Category: contracts.CatFileSystem,
			Source:   contracts.LayerAST,
			Location: contracts.CodeLocation{File: "util/export.go", Line: 88},
		},
	}

	body := gh.RenderComment("scan-abc123", caps, nil, "https://app.tass.dev")

	// Header with count
	if !strings.Contains(body, "3 New Capabilities") {
		t.Errorf("expected '3 New Capabilities' in header:\n%s", body)
	}

	// Table present
	if !strings.Contains(body, "| # |") {
		t.Errorf("missing table header:\n%s", body)
	}

	// Each capability appears
	for _, cap := range caps {
		if !strings.Contains(body, cap.Name) {
			t.Errorf("capability %q not found in comment:\n%s", cap.Name, body)
		}
	}

	// Verify link present
	if !strings.Contains(body, "https://app.tass.dev/verify/scan-abc123") {
		t.Errorf("missing verify link:\n%s", body)
	}

	// Details block
	if !strings.Contains(body, "<details>") {
		t.Errorf("missing <details> block:\n%s", body)
	}

	// Hidden marker
	if !strings.Contains(body, "<!-- tass-scan-id:scan-abc123") {
		t.Errorf("missing hidden scan marker:\n%s", body)
	}
}

func TestRenderComment_SingularPlural(t *testing.T) {
	oneCap := []contracts.Capability{
		{
			ID: "dep:go:github.com/foo/bar", Name: "foo",
			Category: contracts.CatExternalDep, Source: contracts.LayerDependency,
		},
	}
	body := gh.RenderComment("scan-s", oneCap, nil, "http://localhost:8080")
	if !strings.Contains(body, "1 New Capability Needs Review") {
		t.Errorf("singular: expected '1 New Capability Needs Review':\n%s", body)
	}
	if strings.Contains(body, "Capabilities Need") {
		t.Errorf("should be singular, got plural:\n%s", body)
	}
}

func TestRenderComment_LocationWithLine(t *testing.T) {
	caps := []contracts.Capability{
		{
			ID: "x", Name: "test cap",
			Category: contracts.CatNetworkAccess, Source: contracts.LayerAST,
			Location: contracts.CodeLocation{File: "pkg/client.go", Line: 42},
		},
	}
	body := gh.RenderComment("scan-loc", caps, nil, "http://localhost:8080")
	if !strings.Contains(body, "pkg/client.go:42") {
		t.Errorf("location with line not rendered:\n%s", body)
	}
}

func TestRenderComment_LocationNoLine(t *testing.T) {
	caps := []contracts.Capability{
		{
			ID: "y", Name: "dep cap",
			Category: contracts.CatExternalDep, Source: contracts.LayerDependency,
			Location: contracts.CodeLocation{File: "go.mod"},
		},
	}
	body := gh.RenderComment("scan-noline", caps, nil, "http://localhost:8080")
	if !strings.Contains(body, "go.mod") {
		t.Errorf("location without line not rendered:\n%s", body)
	}
}

func TestRenderComment_AllCategories(t *testing.T) {
	// Verify all category emoji/label paths don't panic
	categories := []contracts.CapCategory{
		contracts.CatExternalDep,
		contracts.CatExternalAPI,
		contracts.CatDatabaseOp,
		contracts.CatNetworkAccess,
		contracts.CatFileSystem,
		contracts.CatPrivilege,
	}
	for _, cat := range categories {
		caps := []contracts.Capability{{
			ID: "test", Name: "test", Category: cat, Source: contracts.LayerAST,
		}}
		body := gh.RenderComment("scan-cat", caps, nil, "http://localhost:8080")
		if body == "" {
			t.Errorf("empty comment for category %q", cat)
		}
	}
}

func TestRenderComment_MarkerIsUnique(t *testing.T) {
	// Two renders with different scan IDs must have different markers
	body1 := gh.RenderComment("scan-aaa", nil, nil, "http://localhost:8080")
	body2 := gh.RenderComment("scan-bbb", nil, nil, "http://localhost:8080")

	if !strings.Contains(body1, "scan-aaa") {
		t.Errorf("body1 missing scan-aaa marker")
	}
	if !strings.Contains(body2, "scan-bbb") {
		t.Errorf("body2 missing scan-bbb marker")
	}
	if strings.Contains(body1, "scan-bbb") {
		t.Errorf("body1 should not contain scan-bbb")
	}
}

func TestRenderComment_ContractViolationsSection(t *testing.T) {
	cap := contracts.Capability{
		ID: "ast:go:exec", Name: "exec.Command", Category: contracts.CatPrivilege,
		Source: contracts.LayerAST, ContractViolated: true,
		ContractViolationReason: `category "privilege_pattern" is forbidden by contract`,
	}
	violations := []contract.Violation{
		{
			Capability: cap,
			Rule:       contract.RuleForbidden,
			Reason:     `category "privilege_pattern" is forbidden by contract`,
		},
	}

	body := gh.RenderComment("scan-v", []contracts.Capability{cap}, violations, "http://localhost:8080")

	if !strings.Contains(body, "Contract Violations") {
		t.Errorf("expected 'Contract Violations' section:\n%s", body)
	}
	if !strings.Contains(body, "forbidden") {
		t.Errorf("expected violation rule 'forbidden':\n%s", body)
	}
	// Violated cap should NOT appear in the reviewable section
	if strings.Contains(body, "Need Review") {
		t.Errorf("violated-only comment should not show 'Need Review' section:\n%s", body)
	}
}

func TestRenderComment_AIBadge_Injected(t *testing.T) {
	sig := gh.AISignal{
		IsAIGenerated: true,
		Signals:       []string{"PR author login matches known AI agent: sweep[bot]"},
	}
	body := gh.RenderComment("scan-ai-1", nil, nil, "http://localhost:8080", sig)

	if !strings.Contains(body, "🤖") {
		t.Errorf("expected AI badge emoji in comment:\n%s", body)
	}
	if !strings.Contains(body, "AI-Generated Code Detected") {
		t.Errorf("expected AI badge text in comment:\n%s", body)
	}
	if !strings.Contains(body, "sweep[bot]") {
		t.Errorf("expected signal detail in comment:\n%s", body)
	}
}

func TestRenderComment_AIBadge_NotInjected_WhenFalse(t *testing.T) {
	sig := gh.AISignal{IsAIGenerated: false}
	body := gh.RenderComment("scan-ai-2", nil, nil, "http://localhost:8080", sig)
	if strings.Contains(body, "AI-Generated Code Detected") {
		t.Errorf("AI badge should not appear when IsAIGenerated=false:\n%s", body)
	}
}

func TestRenderComment_AIBadge_NotInjected_WhenOmitted(t *testing.T) {
	// Existing callers pass no AISignal — badge must not appear.
	body := gh.RenderComment("scan-ai-3", nil, nil, "http://localhost:8080")
	if strings.Contains(body, "AI-Generated Code Detected") {
		t.Errorf("AI badge should not appear when no AISignal is passed:\n%s", body)
	}
}

func TestRenderComment_AIBadge_AppearsBeforeCapabilities(t *testing.T) {
	caps := []contracts.Capability{
		{ID: "dep:go:foo", Name: "foo", Category: contracts.CatExternalDep, Source: contracts.LayerDependency},
	}
	sig := gh.AISignal{IsAIGenerated: true, Signals: []string{"PR author login matches known AI agent: claude-code"}}
	body := gh.RenderComment("scan-ai-4", caps, nil, "http://localhost:8080", sig)

	badgeIdx := strings.Index(body, "AI-Generated Code Detected")
	capsIdx := strings.Index(body, "foo")
	if badgeIdx < 0 {
		t.Fatal("AI badge not found in comment")
	}
	if capsIdx < 0 {
		t.Fatal("capability 'foo' not found in comment")
	}
	if badgeIdx > capsIdx {
		t.Errorf("AI badge should appear BEFORE capability table; badge at %d, caps at %d", badgeIdx, capsIdx)
	}
}

func TestRenderComment_MixedViolationsAndReviewable(t *testing.T) {
	violatedCap := contracts.Capability{
		ID: "ast:go:exec", Name: "exec.Command", Category: contracts.CatPrivilege,
		Source: contracts.LayerAST, ContractViolated: true,
		ContractViolationReason: "forbidden",
	}
	reviewableCap := contracts.Capability{
		ID: "dep:go:stripe", Name: "stripe-go", Category: contracts.CatExternalDep,
		Source: contracts.LayerDependency,
	}
	violations := []contract.Violation{
		{Capability: violatedCap, Rule: contract.RuleForbidden, Reason: "forbidden"},
	}

	body := gh.RenderComment("scan-mix", []contracts.Capability{violatedCap, reviewableCap}, violations, "http://localhost:8080")

	if !strings.Contains(body, "Contract Violations") {
		t.Errorf("expected violations section:\n%s", body)
	}
	if !strings.Contains(body, "stripe-go") {
		t.Errorf("expected reviewable cap in comment:\n%s", body)
	}
	if !strings.Contains(body, "Review") {
		t.Errorf("expected review section for non-violated cap:\n%s", body)
	}
}
