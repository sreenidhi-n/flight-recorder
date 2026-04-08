package policy_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/policy"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
	"gopkg.in/yaml.v3"
)

func TestGenerateNetworkPolicy_WithNetworkCaps(t *testing.T) {
	m := &manifest.Manifest{
		Version: "1",
		Capabilities: []manifest.ManifestEntry{
			{ID: "net:http.Post", Name: "net/http.Post", Category: contracts.CatNetworkAccess},
			{ID: "boto3:client:sns", Name: "boto3.client(sns)", Category: contracts.CatExternalAPI},
			{ID: "db:sql.Open", Name: "sql.Open", Category: contracts.CatDatabaseOp},
		},
	}

	got, err := policy.GenerateNetworkPolicy(m, policy.PolicyOpts{AppName: "myapp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(got)

	// Must be parseable YAML.
	var parsed any
	if err := yaml.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n---\n%s", err, out)
	}

	checks := []string{
		"kind: NetworkPolicy",
		"myapp-tass-netpol",
		"app: myapp",
		"policyTypes:",
		"- Egress",
		"port: 53",
		"port: 443",
		"0.0.0.0/0",
		"net/http.Post",
		"boto3.client(sns)",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGenerateNetworkPolicy_EmptyManifest(t *testing.T) {
	m := &manifest.Manifest{Version: "1"}

	got, err := policy.GenerateNetworkPolicy(m, policy.PolicyOpts{AppName: "myapp", Namespace: "production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(got)

	// Must be valid YAML.
	var parsed any
	if err := yaml.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n---\n%s", err, out)
	}

	// DNS must always be present.
	if !strings.Contains(out, "port: 53") {
		t.Errorf("expected DNS egress rule (port 53):\n%s", out)
	}
	// Namespace must appear.
	if !strings.Contains(out, "namespace: production") {
		t.Errorf("expected namespace production:\n%s", out)
	}
	// HTTPS should NOT appear (no network caps).
	if strings.Contains(out, "port: 443") {
		t.Errorf("expected no HTTPS rule for empty manifest, got:\n%s", out)
	}
}

func TestGenerateNetworkPolicy_DefaultNamespace(t *testing.T) {
	m := &manifest.Manifest{Version: "1"}
	got, err := policy.GenerateNetworkPolicy(m, policy.PolicyOpts{AppName: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(got), "namespace: default") {
		t.Errorf("expected default namespace:\n%s", string(got))
	}
}

func TestGenerateNetworkPolicy_DeduplicatesCaps(t *testing.T) {
	m := &manifest.Manifest{
		Version: "1",
		Capabilities: []manifest.ManifestEntry{
			{ID: "net:a", Name: "net/http.Post", Category: contracts.CatNetworkAccess},
			{ID: "net:b", Name: "net/http.Post", Category: contracts.CatNetworkAccess},
		},
	}
	got, err := policy.GenerateNetworkPolicy(m, policy.PolicyOpts{AppName: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should only appear once.
	count := strings.Count(string(got), "net/http.Post")
	if count != 1 {
		t.Errorf("expected 1 occurrence of net/http.Post, got %d:\n%s", count, string(got))
	}
}
