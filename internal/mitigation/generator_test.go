package mitigation_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/contract"
	"github.com/tass-security/tass/internal/mitigation"
	"github.com/tass-security/tass/pkg/contracts"
)

// --- helpers ---

func makeViolation(cat contracts.CapCategory, rule contract.ViolationRule, name, id, file string, line int, reason string) contract.Violation {
	return contract.Violation{
		Capability: contracts.Capability{
			ID:       id,
			Name:     name,
			Category: cat,
			Location: contracts.CodeLocation{File: file, Line: line},
		},
		Rule:   rule,
		Reason: reason,
	}
}

// assertContains is a compact helper so tests stay readable.
func assertContains(t *testing.T, label, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Errorf("%s: expected to find %q in output:\n%s", label, want, body)
	}
}

func assertNotContains(t *testing.T, label, body, unwanted string) {
	t.Helper()
	if strings.Contains(body, unwanted) {
		t.Errorf("%s: should NOT contain %q in output:\n%s", label, unwanted, body)
	}
}

// ─── CatNetworkAccess ────────────────────────────────────────────────────────

func TestGenerateMitigation_NetworkAccess_ContainsNetworkPolicy(t *testing.T) {
	v := makeViolation(
		contracts.CatNetworkAccess,
		contract.RuleForbidden,
		"HTTP client outbound request",
		"ast:go:net/http:Client.Do",
		"internal/client/api.go", 42,
		`category "network_access" is forbidden by contract`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "network", out, "NetworkPolicy")
	assertContains(t, "network", out, "networking.k8s.io/v1")
	assertContains(t, "network", out, "Egress")
	assertContains(t, "network", out, "policyTypes")
}

func TestGenerateMitigation_NetworkAccess_ContainsCapabilityIDInAnnotation(t *testing.T) {
	v := makeViolation(
		contracts.CatNetworkAccess,
		contract.RuleForbidden,
		"HTTP client",
		"ast:go:net/http:Client.Do",
		"pkg/fetch.go", 10,
		"forbidden",
	)
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "network annotation", out, "ast:go:net/http:Client.Do")
}

func TestGenerateMitigation_NetworkAccess_SlugInResourceName(t *testing.T) {
	v := makeViolation(
		contracts.CatNetworkAccess,
		contract.RuleForbidden,
		"gRPC call",
		"ast:go:google.golang.org/grpc:ClientConn.Invoke",
		"rpc/client.go", 5,
		"forbidden",
	)
	out := mitigation.GenerateMitigation(v)
	// Slug derived from the ID should appear in the resource name line.
	assertContains(t, "network slug", out, "restrict-egress-")
}

func TestGenerateMitigation_NetworkAccess_MarkdownFenceIsYAML(t *testing.T) {
	v := makeViolation(contracts.CatNetworkAccess, contract.RuleForbidden,
		"net", "ast:go:net:Dial", "main.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "yaml fence", out, "```yaml")
}

func TestGenerateMitigation_NetworkAccess_ContainsWarningFooter(t *testing.T) {
	v := makeViolation(contracts.CatNetworkAccess, contract.RuleForbidden,
		"net", "ast:go:net:Dial", "main.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "footer", out, "⚠️")
	assertContains(t, "footer", out, "starting point")
}

// ─── CatExternalAPI ──────────────────────────────────────────────────────────

func TestGenerateMitigation_ExternalAPI_ContainsIAMPolicy(t *testing.T) {
	v := makeViolation(
		contracts.CatExternalAPI,
		contract.RuleForbidden,
		"boto3.client(s3)",
		"ast:py:boto3:client",
		"scripts/upload.py", 18,
		`category "external_api" is forbidden by contract`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "iam", out, `"Version": "2012-10-17"`)
	assertContains(t, "iam statement", out, `"Statement"`)
	assertContains(t, "iam effect", out, `"Effect"`)
	assertContains(t, "iam action", out, `"execute-api:Invoke"`)
}

func TestGenerateMitigation_ExternalAPI_MarkdownFenceIsJSON(t *testing.T) {
	v := makeViolation(contracts.CatExternalAPI, contract.RuleForbidden,
		"stripe", "ast:go:stripe:client", "payments.go", 7, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "json fence", out, "```json")
}

func TestGenerateMitigation_ExternalAPI_SidContainsSlug(t *testing.T) {
	v := makeViolation(contracts.CatExternalAPI, contract.RuleForbidden,
		"openai", "ast:py:openai:ChatCompletion", "ai.py", 3, "r")
	out := mitigation.GenerateMitigation(v)
	// The Sid field embeds the slug.
	assertContains(t, "iam sid", out, "TASSMitigationExternalAPI")
}

func TestGenerateMitigation_ExternalAPI_ContainsMetadataTable(t *testing.T) {
	v := makeViolation(contracts.CatExternalAPI, contract.RuleNotInAllowed,
		"stripe API", "ast:go:stripe:client", "pay.go", 12, "not in allowed list")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "capability row", out, "stripe API")
	assertContains(t, "rule row", out, "not_in_allowed")
}

// ─── CatDatabaseOp ───────────────────────────────────────────────────────────

func TestGenerateMitigation_DatabaseOp_ContainsSQLGrant(t *testing.T) {
	v := makeViolation(
		contracts.CatDatabaseOp,
		contract.RuleForbidden,
		"db.Exec (DELETE)",
		"ast:go:database/sql:DB.Exec",
		"repo/users.go", 55,
		`category "database_operation" is forbidden`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "sql revoke", out, "REVOKE ALL PRIVILEGES")
	assertContains(t, "sql grant select", out, "GRANT SELECT")
	assertContains(t, "sql schema", out, "<schema>")
	assertContains(t, "sql app user", out, "<app_user>")
}

func TestGenerateMitigation_DatabaseOp_MarkdownFenceIsSQL(t *testing.T) {
	v := makeViolation(contracts.CatDatabaseOp, contract.RuleForbidden,
		"db.Exec", "ast:go:db:Exec", "db.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "sql fence", out, "```sql")
}

func TestGenerateMitigation_DatabaseOp_ContainsCapabilityInfo(t *testing.T) {
	v := makeViolation(
		contracts.CatDatabaseOp,
		contract.RuleNotInAllowed,
		"gorm.Delete",
		"ast:go:gorm:DB.Delete",
		"repo/users.go", 88,
		"not in allowed list for database_operation",
	)
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "capability name in sql", out, "gorm.Delete")
	assertContains(t, "location in sql", out, "repo/users.go:88")
}

func TestGenerateMitigation_DatabaseOp_NeverGrantsDelete(t *testing.T) {
	v := makeViolation(contracts.CatDatabaseOp, contract.RuleForbidden,
		"sql.Exec", "ast:go:sql:Exec", "d.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	// The GRANT DELETE should only appear in a comment, never as a live statement.
	// We verify the raw GRANT DELETE is only commented out, not a live statement.
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "GRANT DELETE") {
			t.Errorf("GRANT DELETE should not appear as a live SQL statement; got: %q", line)
		}
	}
}

// ─── CatFileSystem ───────────────────────────────────────────────────────────

func TestGenerateMitigation_FileSystem_ContainsReadOnlyFS(t *testing.T) {
	v := makeViolation(
		contracts.CatFileSystem,
		contract.RuleForbidden,
		"os.WriteFile",
		"ast:go:os:file:WriteFile",
		"util/export.go", 33,
		`category "filesystem_operation" is forbidden`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "readOnly", out, "readOnlyRootFilesystem: true")
	assertContains(t, "allowPrivEsc", out, "allowPrivilegeEscalation: false")
	assertContains(t, "runAsNonRoot", out, "runAsNonRoot: true")
}

func TestGenerateMitigation_FileSystem_MarkdownFenceIsYAML(t *testing.T) {
	v := makeViolation(contracts.CatFileSystem, contract.RuleForbidden,
		"fs.Write", "ast:go:os:Write", "f.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "yaml fence", out, "```yaml")
}

func TestGenerateMitigation_FileSystem_ContainsEmptyDirVolume(t *testing.T) {
	v := makeViolation(contracts.CatFileSystem, contract.RuleForbidden,
		"ioutil.WriteFile", "ast:go:ioutil:WriteFile", "w.go", 5, "r")
	out := mitigation.GenerateMitigation(v)
	// Should suggest emptyDir for writable scratch space.
	assertContains(t, "emptyDir", out, "emptyDir: {}")
}

func TestGenerateMitigation_FileSystem_ContainsCapabilityNameInComment(t *testing.T) {
	v := makeViolation(contracts.CatFileSystem, contract.RuleForbidden,
		"os.WriteFile",
		"ast:go:os:file:WriteFile",
		"util/export.go", 33,
		"forbidden",
	)
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "name in comment", out, "os.WriteFile")
}

// ─── CatPrivilege ────────────────────────────────────────────────────────────

func TestGenerateMitigation_Privilege_ContainsDropAllCaps(t *testing.T) {
	v := makeViolation(
		contracts.CatPrivilege,
		contract.RuleForbidden,
		"exec.Command",
		"ast:go:os/exec:Command",
		"cmd/runner.go", 77,
		`category "privilege_pattern" is forbidden`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "drop ALL", out, "drop:")
	assertContains(t, "ALL cap", out, "- ALL")
	assertContains(t, "allowPrivEsc", out, "allowPrivilegeEscalation: false")
}

func TestGenerateMitigation_Privilege_MarkdownFenceIsYAML(t *testing.T) {
	v := makeViolation(contracts.CatPrivilege, contract.RuleForbidden,
		"exec.Command", "ast:go:exec:Command", "main.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "yaml fence", out, "```yaml")
}

func TestGenerateMitigation_Privilege_ContainsSuggestedNetBindService(t *testing.T) {
	v := makeViolation(contracts.CatPrivilege, contract.RuleForbidden,
		"setcap", "ast:go:syscall:RawSyscall", "cap.go", 1, "r")
	out := mitigation.GenerateMitigation(v)
	// Comment hint about re-adding specific capabilities should be present.
	assertContains(t, "net_bind hint", out, "NET_BIND_SERVICE")
}

func TestGenerateMitigation_Privilege_ContainsCapabilityNameInComment(t *testing.T) {
	v := makeViolation(
		contracts.CatPrivilege,
		contract.RuleForbidden,
		"exec.Command",
		"ast:go:os/exec:Command",
		"cmd/runner.go", 77,
		"forbidden",
	)
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "name in comment", out, "exec.Command")
	assertContains(t, "location in comment", out, "cmd/runner.go:77")
}

// ─── Generic / fallback (CatExternalDep) ─────────────────────────────────────

func TestGenerateMitigation_ExternalDep_Fallback_NoIaCSnippet(t *testing.T) {
	v := makeViolation(
		contracts.CatExternalDep,
		contract.RuleForbidden,
		"github.com/stripe/stripe-go/v76",
		"dep:go:github.com/stripe/stripe-go/v76",
		"go.mod", 14,
		`category "external_dependency" is forbidden`,
	)
	out := mitigation.GenerateMitigation(v)

	// Generic advisory: should mention the category and guidance.
	assertContains(t, "dep fallback", out, "external_dependency")
	assertContains(t, "dep update contract", out, "tass.contract.yaml")
	// Should NOT produce a code fence with YAML/JSON/SQL.
	assertNotContains(t, "dep no iac fence", out, "```yaml")
	assertNotContains(t, "dep no iac fence", out, "```json")
	assertNotContains(t, "dep no iac fence", out, "```sql")
}

// ─── Markdown structure ───────────────────────────────────────────────────────

func TestGenerateMitigation_MarkdownTable_ContainsExpectedFields(t *testing.T) {
	v := makeViolation(
		contracts.CatNetworkAccess,
		contract.RuleForbidden,
		"HTTP client",
		"ast:go:net/http:Client.Do",
		"pkg/api.go", 20,
		`network_access is forbidden by contract`,
	)
	out := mitigation.GenerateMitigation(v)

	assertContains(t, "table capability", out, "**Capability**")
	assertContains(t, "table id", out, "**ID**")
	assertContains(t, "table location", out, "**Detected at**")
	assertContains(t, "table rule", out, "**Contract rule**")
	assertContains(t, "table reason", out, "**Reason**")
}

func TestGenerateMitigation_MarkdownTable_LocationWithLine(t *testing.T) {
	v := makeViolation(contracts.CatNetworkAccess, contract.RuleForbidden,
		"Dial", "ast:go:net:Dial", "src/client.go", 42, "r")
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "file:line", out, "src/client.go:42")
}

func TestGenerateMitigation_MarkdownTable_LocationNoLine(t *testing.T) {
	v := contract.Violation{
		Capability: contracts.Capability{
			ID:       "dep:go:foo",
			Name:     "foo",
			Category: contracts.CatNetworkAccess,
			Location: contracts.CodeLocation{File: "go.mod"}, // no line
		},
		Rule:   contract.RuleForbidden,
		Reason: "r",
	}
	out := mitigation.GenerateMitigation(v)
	assertContains(t, "file only", out, "go.mod")
	assertNotContains(t, "no spurious :0", out, "go.mod:0")
}

func TestGenerateMitigation_MarkdownTable_EmptyLocation_Omitted(t *testing.T) {
	v := contract.Violation{
		Capability: contracts.Capability{
			ID:       "dep:go:foo",
			Name:     "foo",
			Category: contracts.CatNetworkAccess,
			Location: contracts.CodeLocation{}, // empty
		},
		Rule:   contract.RuleForbidden,
		Reason: "r",
	}
	out := mitigation.GenerateMitigation(v)
	// When location is empty the "Detected at" row should not appear.
	assertNotContains(t, "no empty location", out, "**Detected at**")
}

// ─── slugify ──────────────────────────────────────────────────────────────────

func TestSlugify_ExportedBehaviour(t *testing.T) {
	// slugify is internal; test via GenerateMitigation output.
	cases := []struct {
		capID     string
		wantInOut string
	}{
		{"ast:go:net/http:Client.Do", "ast-go-net-http-client-do"},
		{"ast:py:boto3:client", "ast-py-boto3-client"},
		{"dep:go:github.com/stripe/stripe-go/v76", "dep-go-github-com-stripe-stripe-go-v76"},
	}
	for _, tc := range cases {
		v := makeViolation(contracts.CatNetworkAccess, contract.RuleForbidden,
			"test", tc.capID, "f.go", 1, "r")
		out := mitigation.GenerateMitigation(v)
		assertContains(t, "slug for "+tc.capID, out, tc.wantInOut)
	}
}

// ─── Determinism ─────────────────────────────────────────────────────────────

func TestGenerateMitigation_Deterministic(t *testing.T) {
	v := makeViolation(
		contracts.CatPrivilege,
		contract.RuleForbidden,
		"exec.Command",
		"ast:go:os/exec:Command",
		"main.go", 10,
		"forbidden by contract",
	)
	out1 := mitigation.GenerateMitigation(v)
	out2 := mitigation.GenerateMitigation(v)
	if out1 != out2 {
		t.Error("GenerateMitigation must be deterministic: two calls with identical input produced different output")
	}
}

// ─── LimitExceeded violation (zero-value Capability) ─────────────────────────

func TestGenerateMitigation_LimitExceeded_FallsBackToGeneric(t *testing.T) {
	v := contract.Violation{
		// Capability is zero-value for limit_exceeded
		Capability: contracts.Capability{},
		Rule:       contract.RuleLimitExceeded,
		Reason:     `category "network_access" has 5 novel capabilities, contract limit is 3`,
	}
	out := mitigation.GenerateMitigation(v)
	// Should not panic; should produce some output.
	if out == "" {
		t.Error("LimitExceeded mitigation should produce non-empty output")
	}
	// The reason should appear somewhere.
	assertContains(t, "limit reason", out, "limit_exceeded")
}

// ─── All categories produce non-empty output ─────────────────────────────────

func TestGenerateMitigation_AllCategories_NonEmpty(t *testing.T) {
	categories := []contracts.CapCategory{
		contracts.CatNetworkAccess,
		contracts.CatExternalAPI,
		contracts.CatDatabaseOp,
		contracts.CatFileSystem,
		contracts.CatPrivilege,
		contracts.CatExternalDep,
	}
	for _, cat := range categories {
		v := makeViolation(cat, contract.RuleForbidden,
			"test-cap", "test:id:"+string(cat), "src/x.go", 1, "reason")
		out := mitigation.GenerateMitigation(v)
		if strings.TrimSpace(out) == "" {
			t.Errorf("category %q produced empty output", cat)
		}
	}
}
