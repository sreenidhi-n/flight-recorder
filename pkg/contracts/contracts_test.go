package contracts_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
	"gopkg.in/yaml.v3"
)

func TestCapabilityRoundTripJSON(t *testing.T) {
	cap := contracts.Capability{
		ID:       "dep:go:github.com/stripe/stripe-go/v76",
		Name:     "stripe-go",
		Category: contracts.CatExternalDep,
		Source:   contracts.LayerDependency,
		Location: contracts.CodeLocation{
			File: "go.mod",
			Line: 14,
		},
		Confidence:  1.0,
		RawEvidence: "require github.com/stripe/stripe-go/v76 v76.3.0",
	}

	data, err := json.Marshal(cap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got contracts.Capability
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.ID != cap.ID {
		t.Errorf("ID: got %q, want %q", got.ID, cap.ID)
	}
	if got.Category != cap.Category {
		t.Errorf("Category: got %q, want %q", got.Category, cap.Category)
	}
	if got.Source != cap.Source {
		t.Errorf("Source: got %q, want %q", got.Source, cap.Source)
	}
}

func TestCapabilityRoundTripYAML(t *testing.T) {
	cap := contracts.Capability{
		ID:       "ast:go:net/http:Client.Do",
		Name:     "HTTP client outbound request",
		Category: contracts.CatNetworkAccess,
		Source:   contracts.LayerAST,
		Location: contracts.CodeLocation{
			File: "internal/client/api.go",
			Line: 42,
		},
		Confidence:  0.95,
		RawEvidence: "http.Client.Do(req)",
	}

	data, err := yaml.Marshal(cap)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var got contracts.Capability
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if got.ID != cap.ID {
		t.Errorf("ID: got %q, want %q", got.ID, cap.ID)
	}
	if got.Name != cap.Name {
		t.Errorf("Name: got %q, want %q", got.Name, cap.Name)
	}
}

func TestCapabilitySetRoundTripJSON(t *testing.T) {
	cs := contracts.CapabilitySet{
		RepoRoot:  "/home/user/myapp",
		ScanTime:  time.Now().UTC().Truncate(time.Second),
		CommitSHA: "abc123",
		Capabilities: []contracts.Capability{
			{ID: "dep:go:golang.org/x/net", Name: "x/net", Category: contracts.CatExternalDep, Source: contracts.LayerDependency},
		},
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got contracts.CapabilitySet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.RepoRoot != cs.RepoRoot {
		t.Errorf("RepoRoot: got %q, want %q", got.RepoRoot, cs.RepoRoot)
	}
	if len(got.Capabilities) != 1 {
		t.Errorf("Capabilities len: got %d, want 1", len(got.Capabilities))
	}
}

func TestVerificationReceiptRoundTripJSON(t *testing.T) {
	receipt := contracts.VerificationReceipt{
		CapabilityID:  "dep:go:github.com/stripe/stripe-go/v76",
		Decision:      contracts.DecisionConfirm,
		Justification: "Payment processing for checkout flow",
		DecidedBy:     "developer@example.com",
		DecidedAt:     time.Now().UTC().Truncate(time.Second),
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got contracts.VerificationReceipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.Decision != contracts.DecisionConfirm {
		t.Errorf("Decision: got %q, want %q", got.Decision, contracts.DecisionConfirm)
	}
	if got.DecidedBy != receipt.DecidedBy {
		t.Errorf("DecidedBy: got %q, want %q", got.DecidedBy, receipt.DecidedBy)
	}
}

func TestAllCategoriesAndLayers(t *testing.T) {
	categories := []contracts.CapCategory{
		contracts.CatExternalDep,
		contracts.CatExternalAPI,
		contracts.CatDatabaseOp,
		contracts.CatNetworkAccess,
		contracts.CatFileSystem,
		contracts.CatPrivilege,
	}
	for _, cat := range categories {
		if cat == "" {
			t.Errorf("empty CapCategory constant")
		}
	}

	layers := []contracts.DetectionLayer{
		contracts.LayerDependency,
		contracts.LayerAST,
	}
	for _, l := range layers {
		if l == "" {
			t.Errorf("empty DetectionLayer constant")
		}
	}
}
