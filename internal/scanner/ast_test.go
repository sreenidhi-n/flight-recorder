package scanner_test

import (
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

// httpClientQuery is the tree-sitter query for Go HTTP client calls.
// Mirrors rules/go/http_client.scm — keep in sync.
const httpClientQuery = `
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  (#match? @pkg "^http$")
  (#match? @method "^(Get|Post|Put|Delete|Head|Do|PostForm)$"))
`

// buildHTTPRule compiles the http_client rule against the Go grammar.
func buildHTTPRule(t *testing.T) map[string][]*scanner.Rule {
	t.Helper()
	q, err := sitter.NewQuery([]byte(httpClientQuery), golang.GetLanguage())
	if err != nil {
		t.Fatalf("compile http_client query: %v", err)
	}
	rule := &scanner.Rule{
		Query:    q,
		Language: "go",
		Name:     "http_client",
		Meta: scanner.RuleMeta{
			Category:      contracts.CatNetworkAccess,
			Name:          "HTTP client outbound request",
			Confidence:    0.95,
			CapID:         "net/http:client",
			SymbolCapture: "method",
		},
	}
	return map[string][]*scanner.Rule{"go": {rule}}
}

// TestASTScanner_HTTPClientDetected verifies the scanner finds http.Get.
func TestASTScanner_HTTPClientDetected(t *testing.T) {
	src := []byte(`package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("https://example.com/api/data")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
`)
	s := scanner.NewASTScanner(buildHTTPRule(t))
	caps, err := s.ScanBytes(src, "main.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	if len(caps) != 1 {
		t.Fatalf("got %d capabilities, want 1", len(caps))
	}

	c := caps[0]
	if c.ID != "ast:go:net/http:client:Get" {
		t.Errorf("ID: got %q, want %q", c.ID, "ast:go:net/http:client:Get")
	}
	if c.Category != contracts.CatNetworkAccess {
		t.Errorf("Category: got %q, want network_access", c.Category)
	}
	if c.Source != contracts.LayerAST {
		t.Errorf("Source: got %q, want layer1_ast", c.Source)
	}
	if c.Confidence != 0.95 {
		t.Errorf("Confidence: got %f, want 0.95", c.Confidence)
	}
	if c.Location.File != "main.go" {
		t.Errorf("Location.File: got %q, want main.go", c.Location.File)
	}
	if c.Location.Line == 0 {
		t.Error("Location.Line should be non-zero")
	}
}

// TestASTScanner_MultipleHTTPMethods verifies different methods get different IDs.
func TestASTScanner_MultipleHTTPMethods(t *testing.T) {
	src := []byte(`package payments

import "net/http"

func sendData() {
	http.Post("https://api.stripe.com/charge", "application/json", nil)
	http.Get("https://api.stripe.com/balance")
}
`)
	s := scanner.NewASTScanner(buildHTTPRule(t))
	caps, err := s.ScanBytes(src, "payments/client.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	if len(caps) != 2 {
		t.Fatalf("got %d capabilities, want 2", len(caps))
	}

	ids := make(map[string]bool)
	for _, c := range caps {
		ids[c.ID] = true
	}
	if !ids["ast:go:net/http:client:Post"] {
		t.Error("missing ast:go:net/http:client:Post")
	}
	if !ids["ast:go:net/http:client:Get"] {
		t.Error("missing ast:go:net/http:client:Get")
	}
}

// TestASTScanner_NoHTTPCalls verifies clean files return no capabilities.
func TestASTScanner_NoHTTPCalls(t *testing.T) {
	src := []byte(`package math

func Add(a, b int) int { return a + b }
func Mul(a, b int) int { return a * b }
`)
	s := scanner.NewASTScanner(buildHTTPRule(t))
	caps, err := s.ScanBytes(src, "math/math.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("got %d capabilities on clean file, want 0", len(caps))
	}
}

// TestASTScanner_Deduplication verifies the same call site is not reported twice.
func TestASTScanner_Deduplication(t *testing.T) {
	// Two calls to http.Get produce only one capability ID since the method
	// is the same. The ID is stable regardless of how many call sites exist.
	src := []byte(`package main

import "net/http"

func fetchA() { http.Get("https://a.example.com") }
func fetchB() { http.Get("https://b.example.com") }
`)
	s := scanner.NewASTScanner(buildHTTPRule(t))
	caps, err := s.ScanBytes(src, "main.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	// Both calls are http.Get → same ID → deduplicated to 1 capability.
	if len(caps) != 1 {
		t.Errorf("got %d capabilities, want 1 (deduplicated by ID)", len(caps))
	}
	if caps[0].ID != "ast:go:net/http:client:Get" {
		t.Errorf("ID: got %q", caps[0].ID)
	}
}

// TestASTScanner_UnknownLanguage verifies unknown languages return nil, not an error.
func TestASTScanner_UnknownLanguage(t *testing.T) {
	s := scanner.NewASTScanner(buildHTTPRule(t))
	caps, err := s.ScanBytes([]byte(`x = 1`), "script.rb", "ruby")
	if err != nil {
		t.Errorf("unexpected error for unknown language: %v", err)
	}
	if caps != nil {
		t.Errorf("expected nil caps for unknown language, got %v", caps)
	}
}
