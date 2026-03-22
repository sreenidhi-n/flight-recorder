package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/tass-security/tass/pkg/contracts"
)

// RequirementsTxtParser implements DepParser for Python's requirements.txt format.
// It handles the common subset of PEP 508/440: package names with optional extras,
// version specifiers, and environment markers. Lines it cannot parse as package
// references (URLs, editable installs, recursive includes) are silently skipped.
type RequirementsTxtParser struct{}

// FilePattern returns the filename handled by this parser.
func (p *RequirementsTxtParser) FilePattern() string { return "requirements.txt" }

// ParseBytes parses requirements.txt content and returns one Capability per package.
// Comments (#), blank lines, editable installs (-e), recursive includes (-r/-c),
// and URL-based requirements are skipped.
func (p *RequirementsTxtParser) ParseBytes(content []byte) ([]contracts.Capability, error) {
	var caps []contracts.Capability
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Strip inline comments and trim whitespace.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Skip options and directives that are not package references.
		if strings.HasPrefix(line, "-") {
			// Covers: -r, -c, -e, --index-url, --extra-index-url, etc.
			continue
		}

		// Skip URL-based requirements (e.g., git+https://..., http://...).
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
			strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "svn+") ||
			strings.HasPrefix(lower, "hg+") || strings.HasPrefix(lower, "bzr+") {
			continue
		}

		name := extractPyPackageName(line)
		if name == "" {
			continue
		}

		normalized := normalizePyName(name)
		id := "dep:python:" + normalized

		caps = append(caps, contracts.Capability{
			ID:          id,
			Name:        normalized,
			Category:    contracts.CatExternalDep,
			Source:      contracts.LayerDependency,
			Location:    contracts.CodeLocation{File: "requirements.txt"},
			Confidence:  1.0,
			RawEvidence: strings.TrimSpace(scanner.Text()), // original line
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("requirements_txt: scan: %w", err)
	}
	return caps, nil
}

// extractPyPackageName extracts the package name from a PEP 508 dependency specifier.
// The name is everything before the first version specifier character or extras bracket.
// Examples:
//
//	"requests>=2.0"          → "requests"
//	"requests[security]>=2"  → "requests"
//	"Django==4.2"            → "Django"
//	"my-package"             → "my-package"
func extractPyPackageName(spec string) string {
	// Name ends at the first of: [, >, <, =, !, ~, ;, whitespace
	end := len(spec)
	for i, ch := range spec {
		switch ch {
		case '[', '>', '<', '=', '!', '~', ';', ' ', '\t':
			if i < end {
				end = i
			}
		}
	}
	name := strings.TrimSpace(spec[:end])
	// A valid Python package name contains only letters, digits, hyphens, underscores, dots.
	// If what we extracted looks empty or starts with a digit (rare but possible in malformed
	// files), skip it.
	if name == "" {
		return ""
	}
	return name
}

// normalizePyName applies PEP 503 normalization: lowercase and collapse runs of
// [-_.] into a single hyphen. This makes "My.Package" and "my-package" the same ID.
func normalizePyName(name string) string {
	var b strings.Builder
	prevWasSep := false
	for _, ch := range strings.ToLower(name) {
		if ch == '-' || ch == '_' || ch == '.' {
			if !prevWasSep {
				b.WriteRune('-')
				prevWasSep = true
			}
		} else {
			b.WriteRune(ch)
			prevWasSep = false
		}
	}
	return b.String()
}
