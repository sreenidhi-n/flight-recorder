package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/tass-security/tass/pkg/contracts"
)

// PackageJSONParser implements DepParser for Node.js package.json.
// It parses both "dependencies" and "devDependencies" keys. Dev dependencies
// are included because compromised lifecycle scripts (postinstall, etc.) in
// dev packages execute during npm install — a real supply-chain attack vector.
type PackageJSONParser struct{}

// FilePattern returns the filename handled by this parser.
func (p *PackageJSONParser) FilePattern() string { return "package.json" }

// packageJSON is the minimal structure needed for dependency extraction.
// Only top-level dependencies and devDependencies are parsed — workspaces
// and nested package.json files are handled as separate files during repo walk.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ParseBytes parses package.json content and returns one Capability per package.
// Both "dependencies" and "devDependencies" are included. Dev dependencies are
// annotated with "devDependency" in RawEvidence.
func (p *PackageJSONParser) ParseBytes(content []byte) ([]contracts.Capability, error) {
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, fmt.Errorf("package_json: unmarshal: %w", err)
	}

	var caps []contracts.Capability

	for name, version := range pkg.Dependencies {
		caps = append(caps, contracts.Capability{
			ID:          "dep:npm:" + name,
			Name:        name,
			Category:    contracts.CatExternalDep,
			Source:      contracts.LayerDependency,
			Location:    contracts.CodeLocation{File: "package.json"},
			Confidence:  1.0,
			RawEvidence: fmt.Sprintf("%s@%s", name, version),
		})
	}

	for name, version := range pkg.DevDependencies {
		// Skip if already added as a production dependency (dedup by ID).
		alreadySeen := false
		for _, c := range caps {
			if c.ID == "dep:npm:"+name {
				alreadySeen = true
				break
			}
		}
		if alreadySeen {
			continue
		}
		caps = append(caps, contracts.Capability{
			ID:          "dep:npm:" + name,
			Name:        name,
			Category:    contracts.CatExternalDep,
			Source:      contracts.LayerDependency,
			Location:    contracts.CodeLocation{File: "package.json"},
			Confidence:  1.0,
			RawEvidence: fmt.Sprintf("%s@%s (devDependency)", name, version),
		})
	}

	return caps, nil
}
