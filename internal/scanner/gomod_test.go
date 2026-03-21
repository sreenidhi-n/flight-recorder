package scanner_test

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

func TestGoModParser_FilePattern(t *testing.T) {
	p := &scanner.GoModParser{}
	if p.FilePattern() != "go.mod" {
		t.Errorf("FilePattern: got %q, want %q", p.FilePattern(), "go.mod")
	}
}

func TestGoModParser_BasicRequire(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22

require (
	github.com/stripe/stripe-go/v76 v76.3.0
	golang.org/x/net v0.20.0
	gopkg.in/yaml.v3 v3.0.1
)
`)
	p := &scanner.GoModParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 3 {
		t.Fatalf("got %d capabilities, want 3", len(caps))
	}

	// Check IDs are in expected format
	ids := map[string]bool{}
	for _, c := range caps {
		ids[c.ID] = true
		if c.Category != contracts.CatExternalDep {
			t.Errorf("%s: Category=%q, want external_dependency", c.ID, c.Category)
		}
		if c.Source != contracts.LayerDependency {
			t.Errorf("%s: Source=%q, want layer0_dependency", c.ID, c.Source)
		}
		if c.Confidence != 1.0 {
			t.Errorf("%s: Confidence=%f, want 1.0", c.ID, c.Confidence)
		}
		if c.Location.File != "go.mod" {
			t.Errorf("%s: Location.File=%q, want go.mod", c.ID, c.Location.File)
		}
	}

	if !ids["dep:go:github.com/stripe/stripe-go/v76"] {
		t.Error("missing dep:go:github.com/stripe/stripe-go/v76")
	}
	if !ids["dep:go:golang.org/x/net"] {
		t.Error("missing dep:go:golang.org/x/net")
	}
	if !ids["dep:go:gopkg.in/yaml.v3"] {
		t.Error("missing dep:go:gopkg.in/yaml.v3")
	}
}

// TestGoModParser_IndirectSkipped verifies that indirect deps are skipped.
func TestGoModParser_IndirectSkipped(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22

require (
	github.com/stripe/stripe-go/v76 v76.3.0
	golang.org/x/sys v0.20.0 // indirect
)
`)
	p := &scanner.GoModParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 1 {
		t.Errorf("got %d capabilities, want 1 (indirect should be skipped)", len(caps))
	}
	if caps[0].ID != "dep:go:github.com/stripe/stripe-go/v76" {
		t.Errorf("unexpected ID: %q", caps[0].ID)
	}
}

// TestGoModParser_ReplaceDirective verifies replace directives are noted in evidence.
func TestGoModParser_ReplaceDirective(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22

require github.com/example/lib v1.0.0

replace github.com/example/lib => ../local-lib
`)
	p := &scanner.GoModParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(caps))
	}
	if !strings.Contains(caps[0].RawEvidence, "replaced by") {
		t.Errorf("RawEvidence should mention replacement, got: %q", caps[0].RawEvidence)
	}
}

// TestGoModParser_ExcludeDirective verifies exclude blocks don't cause parse errors.
func TestGoModParser_ExcludeDirective(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22

require github.com/vulnerable/pkg v1.0.0

exclude github.com/vulnerable/pkg v1.0.0-bad
`)
	p := &scanner.GoModParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes with exclude: %v", err)
	}
	if len(caps) != 1 {
		t.Errorf("got %d capabilities, want 1", len(caps))
	}
}

// TestGoModParser_EmptyRequire verifies an empty require block returns zero capabilities.
func TestGoModParser_EmptyRequire(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22
`)
	p := &scanner.GoModParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("got %d capabilities, want 0", len(caps))
	}
}

// TestGoModParser_InvalidContent verifies parse errors are returned properly.
func TestGoModParser_InvalidContent(t *testing.T) {
	content := []byte(`this is not valid go.mod content!!!`)
	p := &scanner.GoModParser{}
	_, err := p.ParseBytes(content)
	if err == nil {
		t.Error("expected error for invalid go.mod, got nil")
	}
}

// TestGoModParser_IDsDeterministic verifies that running the parser twice
// produces identical IDs (no randomness, no line-number dependency).
func TestGoModParser_IDsDeterministic(t *testing.T) {
	content := []byte(`module github.com/example/myapp

go 1.22

require (
	github.com/some/package v1.0.0
	github.com/other/package/v2 v2.0.0
)
`)
	p := &scanner.GoModParser{}

	caps1, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	caps2, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}

	if len(caps1) != len(caps2) {
		t.Fatalf("different lengths: %d vs %d", len(caps1), len(caps2))
	}
	for i := range caps1 {
		if caps1[i].ID != caps2[i].ID {
			t.Errorf("[%d] non-deterministic ID: %q vs %q", i, caps1[i].ID, caps2[i].ID)
		}
	}
}

// TestParseFile_OwnGoMod parses TASS's own go.mod via the file convenience wrapper.
// This is the dogfooding test — proves the parser works on real content.
func TestParseFile_OwnGoMod(t *testing.T) {
	p := &scanner.GoModParser{}
	caps, err := scanner.ParseFile(p, "../../go.mod")
	if err != nil {
		t.Fatalf("ParseFile on own go.mod: %v", err)
	}

	// TASS's go.mod currently has: gopkg.in/yaml.v3 and golang.org/x/mod as direct deps.
	// We don't hardcode exact count — just verify it returns valid capabilities.
	for _, c := range caps {
		if c.ID == "" {
			t.Error("capability has empty ID")
		}
		if !strings.HasPrefix(c.ID, "dep:go:") {
			t.Errorf("capability ID %q should start with dep:go:", c.ID)
		}
		if c.Category != contracts.CatExternalDep {
			t.Errorf("%s: wrong category %q", c.ID, c.Category)
		}
	}
	t.Logf("TASS own go.mod: %d direct dependencies detected", len(caps))
	for _, c := range caps {
		t.Logf("  %s (%s)", c.ID, c.RawEvidence)
	}
}
