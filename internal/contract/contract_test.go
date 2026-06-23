package contract_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/contract"
	"github.com/tass-security/tass/pkg/contracts"
)

func makeCap(id, name string, cat contracts.CapCategory) contracts.Capability {
	return contracts.Capability{ID: id, Name: name, Category: cat}
}

func makeCapWithEvidence(id, name string, cat contracts.CapCategory, evidence string) contracts.Capability {
	return contracts.Capability{ID: id, Name: name, Category: cat, RawEvidence: evidence}
}

// --- Load ---

func TestLoad_Valid(t *testing.T) {
	data := []byte(`
version: 1
service: payments-service
allowed:
  network_access: ["*.stripe.com", "api.internal.company.com"]
forbidden:
  privilege_pattern: ["*"]
limits:
  external_api: 3
`)
	c, err := contract.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Service != "payments-service" {
		t.Errorf("Service = %q, want %q", c.Service, "payments-service")
	}
	if c.Limits["external_api"] != 3 {
		t.Errorf("Limits[external_api] = %d, want 3", c.Limits["external_api"])
	}
}

func TestLoad_Empty(t *testing.T) {
	c, err := contract.Load(nil)
	if err != nil {
		t.Fatalf("Load(nil): %v", err)
	}
	if c != nil {
		t.Error("Load(nil) should return nil contract")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := contract.Load([]byte("{{not yaml"))
	if err == nil {
		t.Error("Load(invalid yaml) should return error")
	}
}

// --- Check: nil contract ---

func TestCheck_NilContract(t *testing.T) {
	var c *contract.Contract
	caps := []contracts.Capability{makeCap("x", "anything", contracts.CatPrivilege)}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("nil contract: got %d violations, want 0", len(violations))
	}
}

// --- Check: forbidden ---

func TestCheck_Forbidden_WildcardBlocksAll(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"privilege_pattern": {"*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:exec", "exec.Command", contracts.CatPrivilege),
	}
	violations := c.Check(caps)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
	if violations[0].Rule != contract.RuleForbidden {
		t.Errorf("Rule = %q, want %q", violations[0].Rule, contract.RuleForbidden)
	}
	if violations[0].Capability.ID != "ast:go:exec" {
		t.Errorf("Capability.ID = %q, want %q", violations[0].Capability.ID, "ast:go:exec")
	}
}

func TestCheck_Forbidden_PatternMatch(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"filesystem_operation": {"*.Write*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:os:WriteFile", "os.WriteFile", contracts.CatFileSystem),
		makeCap("ast:go:os:Open", "os.Open", contracts.CatFileSystem),
	}
	violations := c.Check(caps)
	// Only WriteFile should be caught (matches *.Write*)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1 (only WriteFile should be forbidden)", len(violations))
	}
}

func TestCheck_Forbidden_OtherCategoryUnaffected(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"privilege_pattern": {"*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:http", "http.Get", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (network_access not forbidden)", len(violations))
	}
}

// --- Check: not_in_allowed ---

func TestCheck_NotInAllowed_BlocksUnlistedCapability(t *testing.T) {
	c := &contract.Contract{
		Allowed: map[string][]string{
			"network_access": {"api.stripe.com"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:http", "HTTP POST to unknown host", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
	if violations[0].Rule != contract.RuleNotInAllowed {
		t.Errorf("Rule = %q, want %q", violations[0].Rule, contract.RuleNotInAllowed)
	}
}

func TestCheck_Allowed_ExactMatchPasses(t *testing.T) {
	c := &contract.Contract{
		Allowed: map[string][]string{
			"network_access": {"api.stripe.com"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:http", "api.stripe.com", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (exact match should pass)", len(violations))
	}
}

func TestCheck_Allowed_GlobMatchPasses(t *testing.T) {
	c := &contract.Contract{
		Allowed: map[string][]string{
			"network_access": {"*.stripe.com"},
		},
	}
	caps := []contracts.Capability{
		makeCapWithEvidence("ast:go:http", "HTTP client outbound call", contracts.CatNetworkAccess, "http.Post(api.stripe.com/v1/charges)"),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (glob *.stripe.com should match evidence)", len(violations))
	}
}

func TestCheck_Allowed_SubstringMatchPasses(t *testing.T) {
	c := &contract.Contract{
		Allowed: map[string][]string{
			"network_access": {"stripe.com"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:http", "HTTP POST to api.stripe.com", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (substring stripe.com in name should pass)", len(violations))
	}
}

func TestCheck_Allowed_CategoryNotInAllowedIsUnrestricted(t *testing.T) {
	c := &contract.Contract{
		Allowed: map[string][]string{
			"network_access": {"api.stripe.com"},
			// database_operation not in allowed → unrestricted
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:sql", "sql.Open", contracts.CatDatabaseOp),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (unrestricted category should pass)", len(violations))
	}
}

// --- Check: limit_exceeded ---

func TestCheck_LimitExceeded(t *testing.T) {
	c := &contract.Contract{
		Limits: map[string]int{"external_api": 2},
	}
	caps := []contracts.Capability{
		makeCap("a", "API 1", contracts.CatExternalAPI),
		makeCap("b", "API 2", contracts.CatExternalAPI),
		makeCap("c", "API 3", contracts.CatExternalAPI),
	}
	violations := c.Check(caps)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
	if violations[0].Rule != contract.RuleLimitExceeded {
		t.Errorf("Rule = %q, want %q", violations[0].Rule, contract.RuleLimitExceeded)
	}
}

func TestCheck_LimitNotExceeded(t *testing.T) {
	c := &contract.Contract{
		Limits: map[string]int{"external_api": 3},
	}
	caps := []contracts.Capability{
		makeCap("a", "API 1", contracts.CatExternalAPI),
		makeCap("b", "API 2", contracts.CatExternalAPI),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (count 2 ≤ limit 3)", len(violations))
	}
}

// --- Check: empty contract ---

func TestCheck_EmptyContract_NoViolations(t *testing.T) {
	c := &contract.Contract{}
	caps := []contracts.Capability{
		makeCap("x", "exec.Command", contracts.CatPrivilege),
		makeCap("y", "http.Post", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 0 {
		t.Errorf("got %d violations, want 0 (empty contract = no-op)", len(violations))
	}
}

// --- ViolatedIDs ---

func TestViolatedIDs_ExcludesLimitViolations(t *testing.T) {
	violations := []contract.Violation{
		{Capability: makeCap("cap1", "exec", contracts.CatPrivilege), Rule: contract.RuleForbidden, Reason: "forbidden"},
		{Rule: contract.RuleLimitExceeded, Reason: "too many"},
	}
	ids := contract.ViolatedIDs(violations)
	if _, ok := ids["cap1"]; !ok {
		t.Error("cap1 should be in violated IDs")
	}
	if len(ids) != 1 {
		t.Errorf("got %d violated IDs, want 1 (limit violations have no cap ID)", len(ids))
	}
}

// --- BP-5: glob semantics for ':' separators ---

// TestMatchesAny_ColonSeparatorGlob verifies that patterns like "boto3:*" correctly
// match capability IDs using ':' as a separator (BP-5 fix: path.Match fails here).
func TestMatchesAny_ColonSeparatorGlob(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"external_api": {"boto3:*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("boto3:client:s3", "boto3 S3 client", contracts.CatExternalAPI),
		makeCap("boto3:resource:ec2", "boto3 EC2 resource", contracts.CatExternalAPI),
		makeCap("openai:chat:completion", "OpenAI chat", contracts.CatExternalAPI),
	}
	violations := c.Check(caps)
	// boto3:client:s3 and boto3:resource:ec2 should be forbidden; openai should not.
	if len(violations) != 2 {
		t.Fatalf("got %d violations, want 2 (both boto3 caps should be forbidden)", len(violations))
	}
	for _, v := range violations {
		if v.Rule != contract.RuleForbidden {
			t.Errorf("expected forbidden rule, got %q", v.Rule)
		}
		if !strings.HasPrefix(v.Capability.ID, "boto3:") {
			t.Errorf("expected only boto3 caps to be forbidden, got %q", v.Capability.ID)
		}
	}
}

// TestMatchesAny_FullIDGlobWithColon verifies '*' in matchGlob crosses ':' boundaries
// when matching the full capability ID. This is the core BP-5 fix: pattern
// "ast:go:net/http:client:*" must match "ast:go:net/http:client:Get".
func TestMatchesAny_FullIDGlobWithColon(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"network_access": {"ast:go:net/http:client:*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("ast:go:net/http:client:Get", "HTTP GET", contracts.CatNetworkAccess),
		makeCap("ast:go:net/http:client:Post", "HTTP POST", contracts.CatNetworkAccess),
	}
	violations := c.Check(caps)
	if len(violations) != 2 {
		t.Fatalf("got %d violations, want 2 (both HTTP client IDs match the pattern)", len(violations))
	}
}

// TestMatchesAny_WildcardDepID verifies that a full dep ID pattern with '*' works.
func TestMatchesAny_WildcardDepID(t *testing.T) {
	c := &contract.Contract{
		Forbidden: map[string][]string{
			"external_dependency": {"dep:go:github.com/stripe/*"},
		},
	}
	caps := []contracts.Capability{
		makeCap("dep:go:github.com/stripe/stripe-go/v76", "stripe-go", contracts.CatExternalDep),
		makeCap("dep:go:github.com/gin-gonic/gin", "gin", contracts.CatExternalDep),
	}
	violations := c.Check(caps)
	// Only stripe should match the pattern; gin should not.
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1 (only stripe-go matches dep:go:github.com/stripe/*)", len(violations))
	}
	if violations[0].Capability.ID != "dep:go:github.com/stripe/stripe-go/v76" {
		t.Errorf("expected stripe cap to be forbidden, got %q", violations[0].Capability.ID)
	}
}
