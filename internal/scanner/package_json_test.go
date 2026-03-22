package scanner_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

func TestPackageJSONParser_FilePattern(t *testing.T) {
	p := &scanner.PackageJSONParser{}
	if p.FilePattern() != "package.json" {
		t.Errorf("FilePattern: got %q, want %q", p.FilePattern(), "package.json")
	}
}

func TestPackageJSONParser_ProductionDeps(t *testing.T) {
	content := []byte(`{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "axios": "^1.6.0",
    "stripe": "^14.0.0"
  }
}`)
	p := &scanner.PackageJSONParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 3 {
		t.Fatalf("got %d capabilities, want 3", len(caps))
	}

	ids := make(map[string]bool)
	for _, c := range caps {
		ids[c.ID] = true
		if c.Category != contracts.CatExternalDep {
			t.Errorf("%s: Category=%q, want external_dependency", c.ID, c.Category)
		}
		if c.Confidence != 1.0 {
			t.Errorf("%s: Confidence=%f, want 1.0", c.ID, c.Confidence)
		}
		if strings.Contains(c.RawEvidence, "devDependency") {
			t.Errorf("%s: production dep should not be marked devDependency", c.ID)
		}
	}

	for _, want := range []string{"dep:npm:express", "dep:npm:axios", "dep:npm:stripe"} {
		if !ids[want] {
			t.Errorf("missing %q", want)
		}
	}
}

func TestPackageJSONParser_DevDeps(t *testing.T) {
	content := []byte(`{
  "name": "my-app",
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}`)
	p := &scanner.PackageJSONParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 2 {
		t.Fatalf("got %d capabilities, want 2", len(caps))
	}

	for _, c := range caps {
		if !strings.Contains(c.RawEvidence, "devDependency") {
			t.Errorf("%s: dev dep should be marked devDependency in RawEvidence", c.ID)
		}
	}
}

// TestPackageJSONParser_BothDepTypes verifies both dependency types are included
// and a package present in both is not duplicated.
func TestPackageJSONParser_BothDepTypes(t *testing.T) {
	content := []byte(`{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "lodash": "^4.17.21"
  }
}`)
	p := &scanner.PackageJSONParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	// lodash appears in both but must only produce one capability.
	if len(caps) != 3 {
		t.Fatalf("got %d capabilities, want 3 (lodash deduped)", len(caps))
	}
}

func TestPackageJSONParser_Empty(t *testing.T) {
	content := []byte(`{"name": "my-app", "version": "1.0.0"}`)
	p := &scanner.PackageJSONParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("got %d capabilities, want 0", len(caps))
	}
}

func TestPackageJSONParser_InvalidJSON(t *testing.T) {
	p := &scanner.PackageJSONParser{}
	_, err := p.ParseBytes([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestPackageJSONParser_IDFormat verifies the dep:npm: ID prefix.
func TestPackageJSONParser_IDFormat(t *testing.T) {
	content := []byte(`{"dependencies": {"@aws-sdk/client-s3": "^3.0.0"}}`)
	p := &scanner.PackageJSONParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(caps))
	}
	if caps[0].ID != "dep:npm:@aws-sdk/client-s3" {
		t.Errorf("ID: got %q, want %q", caps[0].ID, "dep:npm:@aws-sdk/client-s3")
	}
}

// TestPackageJSONParser_DiffIntegration verifies DiffDependencies works end-to-end.
func TestPackageJSONParser_DiffIntegration(t *testing.T) {
	base := []byte(`{"dependencies": {"express": "^4.18.0", "axios": "^1.5.0"}}`)
	pr := []byte(`{"dependencies": {"express": "^4.18.2", "axios": "^1.5.0", "stripe": "^14.0.0"}}`)

	p := &scanner.PackageJSONParser{}
	added, removed, err := scanner.DiffDependencies(base, pr, p)
	if err != nil {
		t.Fatalf("DiffDependencies: %v", err)
	}

	// stripe is new; express version bump doesn't change the ID.
	if len(added) != 1 || added[0].ID != "dep:npm:stripe" {
		t.Errorf("added: got %v, want [dep:npm:stripe]", added)
	}
	if len(removed) != 0 {
		t.Errorf("removed: got %v, want []", removed)
	}
}
