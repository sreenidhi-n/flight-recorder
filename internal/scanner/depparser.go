package scanner

import (
	"fmt"
	"os"

	"github.com/tass-security/tass/pkg/contracts"
)

// DepParser parses a dependency file and returns the capabilities it declares.
// ParseBytes is the primary interface — it works on raw bytes, making it
// suitable for both local file reads and content fetched via the GitHub API.
type DepParser interface {
	// ParseBytes parses dependency file content from raw bytes.
	ParseBytes(content []byte) ([]contracts.Capability, error)

	// FilePattern returns the filename this parser handles (e.g., "go.mod").
	FilePattern() string
}

// ParseFile is a convenience wrapper that reads a file from disk and delegates
// to the parser's ParseBytes. Use ParseBytes directly for GitHub API content.
func ParseFile(p DepParser, filePath string) ([]contracts.Capability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseFile: read %q: %w", filePath, err)
	}
	caps, err := p.ParseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseFile: parse %q: %w", filePath, err)
	}
	return caps, nil
}
