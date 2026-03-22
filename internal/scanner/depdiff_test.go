package scanner_test

import (
	"testing"

	"github.com/tass-security/tass/internal/scanner"
)

// baseGoMod has 10 direct dependencies.
var baseGoMod = []byte(`module github.com/example/myapp

go 1.22

require (
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/go-chi/chi/v5 v5.0.11
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.2
	github.com/prometheus/client_golang v1.18.0
	github.com/redis/go-redis/v9 v9.4.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.19.0
	gopkg.in/yaml.v3 v3.0.1
)
`)

// prGoMod has 12 dependencies: base minus github.com/stretchr/testify, plus 3 new ones.
var prGoMod = []byte(`module github.com/example/myapp

go 1.22

require (
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/go-chi/chi/v5 v5.0.11
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.2
	github.com/prometheus/client_golang v1.18.0
	github.com/redis/go-redis/v9 v9.4.0
	github.com/sendgrid/sendgrid-go v3.14.0+incompatible
	github.com/stripe/stripe-go/v76 v76.3.0
	golang.org/x/crypto v0.19.0
	golang.org/x/net v0.21.0
	gopkg.in/yaml.v3 v3.0.1
)
`)

func TestDiffDependencies_StandardDiff(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(baseGoMod, prGoMod, parser)
	if err != nil {
		t.Fatalf("DiffDependencies: %v", err)
	}

	if len(added) != 3 {
		t.Errorf("added: got %d, want 3", len(added))
		for _, c := range added {
			t.Logf("  + %s", c.ID)
		}
	}
	if len(removed) != 1 {
		t.Errorf("removed: got %d, want 1", len(removed))
		for _, c := range removed {
			t.Logf("  - %s", c.ID)
		}
	}

	// Verify specific IDs.
	addedIDs := make(map[string]bool)
	for _, c := range added {
		addedIDs[c.ID] = true
	}
	for _, want := range []string{
		"dep:go:github.com/sendgrid/sendgrid-go",
		"dep:go:github.com/stripe/stripe-go/v76",
		"dep:go:golang.org/x/net",
	} {
		if !addedIDs[want] {
			t.Errorf("added: missing %q", want)
		}
	}

	if removed[0].ID != "dep:go:github.com/stretchr/testify" {
		t.Errorf("removed[0].ID: got %q, want dep:go:github.com/stretchr/testify", removed[0].ID)
	}
}

// TestDiffDependencies_NilBase covers new-file case: everything in pr is added.
func TestDiffDependencies_NilBase(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(nil, prGoMod, parser)
	if err != nil {
		t.Fatalf("DiffDependencies nil base: %v", err)
	}

	if len(removed) != 0 {
		t.Errorf("removed: got %d, want 0", len(removed))
	}
	if len(added) != 12 {
		t.Errorf("added: got %d, want 12 (all pr deps)", len(added))
	}
}

// TestDiffDependencies_NilPR covers deleted-file case: everything in base is removed.
func TestDiffDependencies_NilPR(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(baseGoMod, nil, parser)
	if err != nil {
		t.Fatalf("DiffDependencies nil pr: %v", err)
	}

	if len(added) != 0 {
		t.Errorf("added: got %d, want 0", len(added))
	}
	if len(removed) != 10 {
		t.Errorf("removed: got %d, want 10 (all base deps)", len(removed))
	}
}

// TestDiffDependencies_BothNil covers the degenerate case.
func TestDiffDependencies_BothNil(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(nil, nil, parser)
	if err != nil {
		t.Fatalf("DiffDependencies both nil: %v", err)
	}
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("both nil: got added=%d removed=%d, want 0/0", len(added), len(removed))
	}
}

// TestDiffDependencies_Idempotent verifies that diffing identical files returns no changes.
func TestDiffDependencies_Idempotent(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(baseGoMod, baseGoMod, parser)
	if err != nil {
		t.Fatalf("DiffDependencies same content: %v", err)
	}
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("same content: got added=%d removed=%d, want 0/0", len(added), len(removed))
	}
}

// TestDiffDependencies_SortedOutput verifies results are sorted by ID for determinism.
func TestDiffDependencies_SortedOutput(t *testing.T) {
	parser := &scanner.GoModParser{}
	added, removed, err := scanner.DiffDependencies(baseGoMod, prGoMod, parser)
	if err != nil {
		t.Fatalf("DiffDependencies: %v", err)
	}

	for i := 1; i < len(added); i++ {
		if added[i].ID < added[i-1].ID {
			t.Errorf("added not sorted at index %d: %q < %q", i, added[i].ID, added[i-1].ID)
		}
	}
	for i := 1; i < len(removed); i++ {
		if removed[i].ID < removed[i-1].ID {
			t.Errorf("removed not sorted at index %d: %q < %q", i, removed[i].ID, removed[i-1].ID)
		}
	}
}
