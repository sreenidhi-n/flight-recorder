package scanner

import (
	"fmt"

	"github.com/tass-security/tass/pkg/contracts"
	"golang.org/x/mod/modfile"
)

// GoModParser implements DepParser for Go's go.mod format.
// It uses golang.org/x/mod/modfile — the same parser used by the Go toolchain.
type GoModParser struct{}

// FilePattern returns the filename handled by this parser.
func (p *GoModParser) FilePattern() string { return "go.mod" }

// ParseBytes parses go.mod content and returns one Capability per require directive.
// Replace and exclude directives are noted in RawEvidence but do not generate
// additional capabilities — the canonical module path is what matters.
func (p *GoModParser) ParseBytes(content []byte) ([]contracts.Capability, error) {
	f, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return nil, fmt.Errorf("gomod: parse: %w", err)
	}

	// Build a set of replaced module paths so we can annotate them.
	replaced := make(map[string]string) // original path → replacement
	for _, r := range f.Replace {
		replaced[r.Old.Path] = r.New.Path
	}

	var caps []contracts.Capability
	for _, req := range f.Require {
		if req.Indirect {
			// Indirect dependencies are transitive — they weren't explicitly
			// chosen by the developer, so we skip them for now.
			// Future: make this configurable via a manifest flag.
			continue
		}

		id := capabilityID(req.Mod.Path)
		evidence := fmt.Sprintf("require %s %s", req.Mod.Path, req.Mod.Version)
		if repl, ok := replaced[req.Mod.Path]; ok {
			evidence += fmt.Sprintf(" (replaced by %s)", repl)
		}

		caps = append(caps, contracts.Capability{
			ID:          id,
			Name:        moduleName(req.Mod.Path),
			Category:    contracts.CatExternalDep,
			Source:      contracts.LayerDependency,
			Location:    contracts.CodeLocation{File: "go.mod"},
			Confidence:  1.0,
			RawEvidence: evidence,
		})
	}

	return caps, nil
}

// capabilityID generates a deterministic, stable ID for a Go module dependency.
// Format: dep:go:<module_path> — never includes version or line numbers.
func capabilityID(modulePath string) string {
	return "dep:go:" + modulePath
}

// moduleName extracts a short human-readable name from a module path.
// e.g., "github.com/stripe/stripe-go/v76" → "stripe-go/v76"
func moduleName(modulePath string) string {
	// Walk backwards through path segments to find a meaningful short name.
	// For paths like "github.com/foo/bar/v2", we want "bar/v2".
	// For paths like "golang.org/x/net", we want "x/net".
	start := 0
	slashes := 0
	for i := len(modulePath) - 1; i >= 0; i-- {
		if modulePath[i] == '/' {
			slashes++
			if slashes == 2 {
				start = i + 1
				break
			}
		}
	}
	if start > 0 {
		return modulePath[start:]
	}
	return modulePath
}
