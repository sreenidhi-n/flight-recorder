package scanner_test

import (
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

func TestRequirementsTxtParser_FilePattern(t *testing.T) {
	p := &scanner.RequirementsTxtParser{}
	if p.FilePattern() != "requirements.txt" {
		t.Errorf("FilePattern: got %q, want %q", p.FilePattern(), "requirements.txt")
	}
}

func TestRequirementsTxtParser_Basic(t *testing.T) {
	content := []byte(`# Web framework
Django==4.2.7
requests>=2.28.0
flask[async]>=2.3.0

# Database
psycopg2-binary==2.9.9
SQLAlchemy>=2.0

# Utilities
python-dotenv~=1.0
`)
	p := &scanner.RequirementsTxtParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	if len(caps) != 6 {
		t.Fatalf("got %d capabilities, want 6", len(caps))
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
	}

	for _, want := range []string{
		"dep:python:django",
		"dep:python:requests",
		"dep:python:flask",
		"dep:python:psycopg2-binary",
		"dep:python:sqlalchemy",
		"dep:python:python-dotenv",
	} {
		if !ids[want] {
			t.Errorf("missing %q", want)
		}
	}
}

// TestRequirementsTxtParser_PEP503Normalization verifies that different spellings
// of the same package name produce identical IDs (PEP 503).
func TestRequirementsTxtParser_PEP503Normalization(t *testing.T) {
	content := []byte(`My.Package==1.0
my_other.lib>=2.0
UPPER-CASE==3.0
`)
	p := &scanner.RequirementsTxtParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	want := map[string]bool{
		"dep:python:my-package":  true,
		"dep:python:my-other-lib": true,
		"dep:python:upper-case":  true,
	}
	for _, c := range caps {
		if !want[c.ID] {
			t.Errorf("unexpected ID %q", c.ID)
		}
	}
}

// TestRequirementsTxtParser_SkipsDirectives verifies options and directives are skipped.
func TestRequirementsTxtParser_SkipsDirectives(t *testing.T) {
	content := []byte(`--index-url https://pypi.org/simple
-r base_requirements.txt
-c constraints.txt
-e .
requests==2.28.0
`)
	p := &scanner.RequirementsTxtParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 1 || caps[0].ID != "dep:python:requests" {
		t.Errorf("got %d caps, want 1 (requests only); caps: %v", len(caps), caps)
	}
}

// TestRequirementsTxtParser_SkipsURLs verifies URL-based requirements are skipped.
func TestRequirementsTxtParser_SkipsURLs(t *testing.T) {
	content := []byte(`git+https://github.com/user/repo.git@main
https://example.com/package.whl
http://internal.corp/lib.tar.gz
requests==2.28.0
`)
	p := &scanner.RequirementsTxtParser{}
	caps, err := p.ParseBytes(content)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 1 || caps[0].ID != "dep:python:requests" {
		t.Errorf("got %d caps, want 1 (requests only)", len(caps))
	}
}

// TestRequirementsTxtParser_Empty verifies an empty file returns zero capabilities.
func TestRequirementsTxtParser_Empty(t *testing.T) {
	p := &scanner.RequirementsTxtParser{}
	caps, err := p.ParseBytes([]byte("# just a comment\n\n"))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("got %d caps, want 0", len(caps))
	}
}

// TestRequirementsTxtParser_DiffIntegration verifies DiffDependencies works
// end-to-end with the requirements.txt parser.
func TestRequirementsTxtParser_DiffIntegration(t *testing.T) {
	base := []byte(`requests==2.28.0
flask==2.3.0
`)
	pr := []byte(`requests==2.29.0
flask==2.3.0
stripe==7.0.0
`)
	p := &scanner.RequirementsTxtParser{}
	added, removed, err := scanner.DiffDependencies(base, pr, p)
	if err != nil {
		t.Fatalf("DiffDependencies: %v", err)
	}

	// stripe is new; requests version bump doesn't change the ID.
	if len(added) != 1 || added[0].ID != "dep:python:stripe" {
		t.Errorf("added: got %v, want [dep:python:stripe]", added)
	}
	if len(removed) != 0 {
		t.Errorf("removed: got %v, want []", removed)
	}
}
