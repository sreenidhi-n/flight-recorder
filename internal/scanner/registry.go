package scanner

// DefaultRegistry maps dependency filenames to their parsers.
// Add new parsers here when support for additional ecosystems is added.
var DefaultRegistry = map[string]DepParser{
	"go.mod":           &GoModParser{},
	"requirements.txt": &RequirementsTxtParser{},
	"package.json":     &PackageJSONParser{},
}
