package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/policy"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

func TestGenerateIAMPolicy_WithBotoCaps(t *testing.T) {
	m := &manifest.Manifest{
		Version: "1",
		Capabilities: []manifest.ManifestEntry{
			{ID: "boto3:client:s3", Name: "boto3.client(s3)", Category: contracts.CatNetworkAccess},
			{ID: "boto3:client:dynamodb", Name: "boto3.client(dynamodb)", Category: contracts.CatExternalAPI},
		},
	}

	got, err := policy.GenerateIAMPolicy(m, policy.PolicyOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n---\n%s", err, string(got))
	}

	out := string(got)
	if !strings.Contains(out, `"2012-10-17"`) {
		t.Errorf("expected Version 2012-10-17:\n%s", out)
	}
	if !strings.Contains(out, "s3:*") {
		t.Errorf("expected s3:* action:\n%s", out)
	}
	if !strings.Contains(out, "dynamodb:*") {
		t.Errorf("expected dynamodb:* action:\n%s", out)
	}
	if !strings.Contains(out, `"Allow"`) {
		t.Errorf("expected Allow effect:\n%s", out)
	}
}

func TestGenerateIAMPolicy_NoAWSCaps(t *testing.T) {
	m := &manifest.Manifest{
		Version: "1",
		Capabilities: []manifest.ManifestEntry{
			{ID: "net:http", Name: "net/http.Post", Category: contracts.CatNetworkAccess},
		},
	}

	got, err := policy.GenerateIAMPolicy(m, policy.PolicyOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n---\n%s", err, string(got))
	}

	// Statement should be absent (no AWS caps detected).
	stmts, _ := parsed["Statement"]
	if stmts != nil {
		t.Errorf("expected no Statement for non-AWS caps, got: %v", stmts)
	}
}

func TestGenerateIAMPolicy_EmptyManifest(t *testing.T) {
	m := &manifest.Manifest{Version: "1"}

	got, err := policy.GenerateIAMPolicy(m, policy.PolicyOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n---\n%s", err, string(got))
	}
}
