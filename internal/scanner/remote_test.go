package scanner_test

import (
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

func TestScanRemote_LayerZero_NewDep(t *testing.T) {
	s := scanner.New(scanner.DefaultRegistry, nil) // Layer 1 disabled

	goModHead := []byte(`module github.com/example/app

go 1.22

require (
	github.com/stripe/stripe-go/v76 v76.0.0
	github.com/gin-gonic/gin v1.9.1
)
`)
	goModBase := []byte(`module github.com/example/app

go 1.22

require github.com/gin-gonic/gin v1.9.1
`)

	headFiles := map[string][]byte{
		"go.mod": goModHead,
	}
	baseDeps := map[string][]byte{
		"go.mod": goModBase,
	}

	cs, err := s.ScanRemote(headFiles, baseDeps)
	if err != nil {
		t.Fatalf("ScanRemote: %v", err)
	}

	// Only stripe-go should be novel (gin is in base)
	if len(cs.Capabilities) != 1 {
		t.Fatalf("expected 1 novel capability, got %d: %v", len(cs.Capabilities), cs.Capabilities)
	}
	if cs.Capabilities[0].Category != contracts.CatExternalDep {
		t.Errorf("category: got %q, want external_dependency", cs.Capabilities[0].Category)
	}
	if cs.Capabilities[0].Source != contracts.LayerDependency {
		t.Errorf("source: got %q, want layer0_dependency", cs.Capabilities[0].Source)
	}
	// ID should reference stripe
	id := cs.Capabilities[0].ID
	if id == "" {
		t.Error("capability ID should not be empty")
	}
}

func TestScanRemote_LayerZero_NewFile(t *testing.T) {
	// New dep file (no base) — all deps are novel
	s := scanner.New(scanner.DefaultRegistry, nil)

	headFiles := map[string][]byte{
		"requirements.txt": []byte("requests==2.31.0\nflask==3.0.0\n"),
	}
	baseDeps := map[string][]byte{
		"requirements.txt": nil, // new file in PR
	}

	cs, err := s.ScanRemote(headFiles, baseDeps)
	if err != nil {
		t.Fatalf("ScanRemote: %v", err)
	}

	if len(cs.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(cs.Capabilities))
	}
}

func TestScanRemote_NoChangedDepFiles_NoCapabilities(t *testing.T) {
	s := scanner.New(scanner.DefaultRegistry, nil)

	// headFiles has only a source file, no dep files
	headFiles := map[string][]byte{
		"main.go": []byte(`package main
func main() {}
`),
	}
	baseDeps := map[string][]byte{}

	cs, err := s.ScanRemote(headFiles, baseDeps)
	if err != nil {
		t.Fatalf("ScanRemote: %v", err)
	}

	// No dep parser will match main.go, and AST scanner is nil
	if len(cs.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(cs.Capabilities))
	}
}

func TestScanRemote_MultipleDeps_Deduplicated(t *testing.T) {
	s := scanner.New(scanner.DefaultRegistry, nil)

	// Same package appears in both go.mod files (hypothetically)
	goModHead := []byte(`module github.com/example/app
go 1.22
require (
	github.com/lib/pq v1.10.9
	github.com/go-redis/redis/v9 v9.0.0
)
`)
	reqHead := []byte("requests==2.31.0\n")

	headFiles := map[string][]byte{
		"go.mod":           goModHead,
		"requirements.txt": reqHead,
	}
	baseDeps := map[string][]byte{
		"go.mod":           nil, // both new
		"requirements.txt": nil,
	}

	cs, err := s.ScanRemote(headFiles, baseDeps)
	if err != nil {
		t.Fatalf("ScanRemote: %v", err)
	}

	// 2 Go deps + 1 Python dep = 3 total, no duplicates
	if len(cs.Capabilities) != 3 {
		t.Errorf("expected 3 capabilities, got %d: %v", len(cs.Capabilities), remoteCapIDs(cs.Capabilities))
	}

	// Check for duplicates by ID
	seen := make(map[string]int)
	for _, c := range cs.Capabilities {
		seen[c.ID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("duplicate capability ID %q (count=%d)", id, count)
		}
	}
}

func TestScanRemote_LocationSet(t *testing.T) {
	s := scanner.New(scanner.DefaultRegistry, nil)

	headFiles := map[string][]byte{
		"services/payment/go.mod": []byte(`module github.com/example/payment
go 1.22
require github.com/stripe/stripe-go/v76 v76.0.0
`),
	}
	baseDeps := map[string][]byte{
		"services/payment/go.mod": nil,
	}

	cs, err := s.ScanRemote(headFiles, baseDeps)
	if err != nil {
		t.Fatalf("ScanRemote: %v", err)
	}

	if len(cs.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(cs.Capabilities))
	}
	if cs.Capabilities[0].Location.File != "services/payment/go.mod" {
		t.Errorf("location.file: got %q, want services/payment/go.mod",
			cs.Capabilities[0].Location.File)
	}
}

func remoteCapIDs(caps []contracts.Capability) []string {
	ids := make([]string, len(caps))
	for i, c := range caps {
		ids[i] = c.ID
	}
	return ids
}
